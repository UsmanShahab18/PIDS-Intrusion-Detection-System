"""
PIDS - Model Retraining API Views
Connects ModelRetrainer backend to React frontend.
"""
import threading
from datetime import datetime
from rest_framework.decorators import api_view
from rest_framework.response import Response
from api.auth_utils import jwt_required, admin_required
from api.management.commands.pids_core.model_retraining import get_retraining_service

# In-memory training state
_state = {
    'is_training': False,
    'progress': 0,
    'stage': '',
    'log': [],
    'history': [],
}


def _log(msg, level='info'):
    _state['log'].append({'time': datetime.now().strftime('%H:%M:%S'), 'message': msg, 'level': level})
    if len(_state['log']) > 50:
        _state['log'] = _state['log'][-50:]


@api_view(['GET'])
@jwt_required
def data_stats(request):
    from api.models import TrafficLog
    from django.db.models import Count, Q
    from django.core.cache import cache
    try:
        cached = cache.get('pids_data_stats')
        if cached:
            return Response(cached)

        base_qs = TrafficLog.objects.exclude(features__isnull=True).exclude(features={})
        # Single-pass conditional aggregation — one scan instead of 4 separate
        # counts, each of which re-ran the expensive JSON features filter.
        agg = base_qs.aggregate(
            total=Count('id'),
            used=Count('id', filter=Q(used_for_training=True)),
            unused_attacks=Count('id', filter=Q(used_for_training=False, status='Attack')),
            unused_normal=Count('id', filter=Q(used_for_training=False) & ~Q(status='Attack')),
        )
        total = agg['total'] or 0
        used = agg['used'] or 0
        unused_attacks = agg['unused_attacks'] or 0
        unused_normal = agg['unused_normal'] or 0
        unused_total = unused_attacks + unused_normal
        
        # Balanced preview: 1/3 attack rule
        balanced_attacks = unused_attacks
        balanced_normal  = min(unused_normal, balanced_attacks * 2)
        balanced_total   = balanced_attacks + balanced_normal
        
        data = {
            'available_for_training': unused_total,
            'available_attacks': unused_attacks,
            'available_normal': unused_normal,
            'used_for_training': used,
            'total_logs': TrafficLog.objects.count(),
            'total_with_features': total,
            'balanced_preview': {
                'attacks': balanced_attacks,
                'normal': balanced_normal,
                'total': balanced_total,
                'attack_ratio': round(balanced_attacks / balanced_total * 100, 1) if balanced_total > 0 else 0,
            }
        }
        cache.set('pids_data_stats', data, 10)  # 10s cache → instant repeat loads
        return Response(data)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


def _resolve_engine_choice(request_engine):
    """
    Validate and normalise the engine choice from a request body.
    Defaults to whichever engine the registry currently has active.
    """
    if request_engine in ('ml', 'dl'):
        return request_engine
    try:
        from api.detection.engines.engine_registry import get_registry
        return get_registry().get_active_engine().name
    except Exception:
        return 'ml'


@api_view(['GET'])
@jwt_required
def training_status(request):
    # Engine name reported in status reflects the actively-training one
    # if any; otherwise the registry's active engine. Frontend uses
    # this to pick which retrainer's progress endpoint to poll.
    engine = _state.get('engine') or _resolve_engine_choice(None)
    svc = get_retraining_service(engine)
    prog = svc.get_progress()
    return Response({
        'is_training': _state['is_training'],
        'engine': engine,
        'progress': prog.get('percent', 0),
        'stage': prog.get('message', ''),
        'log': _state['log'][-20:],
    })


@api_view(['POST'])
@admin_required
def start_training(request):
    if _state['is_training']:
        return Response({'error': 'Training already in progress'}, status=400)
    config = request.data or {}
    engine = _resolve_engine_choice(config.get('engine'))

    def _run():
        try:
            _state['is_training'] = True
            _state['engine'] = engine
            _state['log'] = []
            _log(f'Starting retraining pipeline ({engine.upper()} engine)...')
            svc = get_retraining_service(engine)
            _log(f"GPU: {'Yes' if svc.has_gpu else 'No (CPU)'}")
            if config.get('max_samples'):
                _log(f"Max samples: {config['max_samples']:,}")
            if config.get('max_percentage', 100) < 100:
                _log(f"Percentage: {config['max_percentage']}%")
            results = svc.retrain(config)
            if results.get('success'):
                stage1_label = results['stage1']['model']
                stage2_label = results['stage2']['model']
                _log(f"Stage 1 {stage1_label}: {results['stage1']['accuracy_pct']}")
                _log(f"Stage 2 {stage2_label}: {results['stage2']['accuracy_pct']}")
                _log(f"Duration: {results['duration_seconds']}s")
                _log(f'{engine.upper()} retraining complete!')

                # Reset the engine registry so freshly-saved models
                # are picked up by inference without a Django restart.
                try:
                    from api.detection.engines.engine_registry import get_registry
                    get_registry().reload_engines()
                    _log('Engine registry reloaded — new models will serve next prediction.')
                except Exception as exc:
                    _log(f'Registry reload failed: {exc}', 'warning')

                # History entry: tolerate ML's classification_report
                # shape AND DL's lighter {val_loss, epochs} shape.
                def _f1(metrics, fallback):
                    if isinstance(metrics, dict):
                        wavg = metrics.get('weighted avg')
                        if isinstance(wavg, dict):
                            return wavg.get('f1-score', fallback)
                    return fallback

                _state['history'].append({
                    'timestamp': results['timestamp'],
                    'engine': engine,
                    'samples': results['total_samples'],
                    'stage1_metrics': {
                        'accuracy': results['stage1']['accuracy'],
                        'f1_score': _f1(results['stage1'].get('report'), results['stage1']['accuracy']),
                    },
                    'stage2_metrics': {
                        'accuracy': results['stage2']['accuracy'],
                        'f1_score': _f1(results['stage2'].get('report'), results['stage2']['accuracy']),
                    },
                    'duration_seconds': results['duration_seconds'],
                })
            else:
                _log(f"Failed: {results.get('error')}", 'error')
        except Exception as e:
            _log(f"Error: {e}", 'error')
        finally:
            _state['is_training'] = False

    threading.Thread(target=_run, daemon=True).start()
    return Response({'status': 'started', 'engine': engine})


@api_view(['POST'])
@admin_required
def cancel_training(request):
    if not _state['is_training']:
        return Response({'error': 'No training in progress'}, status=400)
    try:
        svc = get_retraining_service()
        svc.cancel()
        _log('Training cancellation requested by user', 'warning')
        return Response({'status': 'cancelling'})
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@jwt_required
def training_history(request):
    return Response(_state['history'])


@api_view(['GET'])
@jwt_required
def model_backups(request):
    try:
        svc = get_retraining_service()
        return Response([{
            'name': b['name'], 'timestamp': b['timestamp'],
            'files': b['files'], 'file_count': len(b['files']),
        } for b in svc.list_backups()])
    except Exception:
        return Response([])


@api_view(['POST'])
@admin_required
def restore_backup(request):
    name = request.data.get('backup_name')
    if not name:
        return Response({'error': 'backup_name required'}, status=400)
    try:
        svc = get_retraining_service()
        for b in svc.list_backups():
            if b['name'] == name:
                result = svc.restore_backup(b['path'])
                if result.get('success'):
                    _log(f"Restored: {name}")
                    return Response({'status': 'restored', 'files': result['restored']})
                return Response({'error': result.get('error')}, status=500)
        return Response({'error': f'Backup "{name}" not found'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@admin_required
def reset_flags(request):
    try:
        from api.models import TrafficLog
        count = 0
        try:
            count = TrafficLog.objects.filter(used_for_training=True).update(used_for_training=False)
        except Exception:
            pass
        return Response({'status': 'reset', 'count': count})
    except Exception as e:
        return Response({'error': str(e)}, status=500)