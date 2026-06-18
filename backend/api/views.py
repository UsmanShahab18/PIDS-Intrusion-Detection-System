"""
PIDS - API Views
Handles all REST API endpoints including reports
"""
from rest_framework.decorators import api_view, action
from rest_framework.response import Response
from rest_framework import viewsets, status
from django.http import HttpResponse, JsonResponse
from django.db.models import Count, Q, F
from datetime import datetime, timedelta
import csv
import json
import logging

logger = logging.getLogger(__name__)

from .models import TrafficLog, SystemAlert
from .serializers import TrafficLogSerializer, SystemAlertSerializer, StatsSerializer
from .auth_utils import jwt_required


@api_view(['GET'])
@jwt_required
def get_attack_groups(request):
    """
    Get ALL attacks from DB, grouped by source IP (server-side aggregation).
    Returns grouped attack data without fetching all individual rows.
    """
    from django.db.models import Max, Min, Avg
    
    # Aggregate attacks by src_ip
    groups = (
        TrafficLog.objects
        .filter(status='Attack')
        .values('src_ip')
        .annotate(
            count=Count('id'),
            latest=Max('timestamp'),
            earliest=Min('timestamp'),
            avg_confidence=Avg('confidence'),
        )
        .order_by('-latest')
    )
    
    result = []
    for g in groups:
        # Get the most recent log for this src_ip (for details)
        latest_log = (
            TrafficLog.objects
            .filter(status='Attack', src_ip=g['src_ip'])
            .order_by('-timestamp')
            .values('id', 'dst_ip', 'dst_port', 'protocol', 'prediction',
                    'confidence', 'timestamp', 'features', 'llm_analyzed',
                    'llm_result', 'attack_type', 'acknowledged', 'acknowledged_at')
            .first()
        )
        
        # Get unique attack types for this IP
        attack_types = list(
            TrafficLog.objects
            .filter(status='Attack', src_ip=g['src_ip'])
            .values_list('prediction', flat=True)
            .distinct()
        )
        
        # Get unique dst_ports targeted
        dst_ports = list(
            TrafficLog.objects
            .filter(status='Attack', src_ip=g['src_ip'])
            .values_list('dst_port', flat=True)
            .distinct()[:10]
        )
        
        if latest_log:
            result.append({
                'id': latest_log['id'],
                'src_ip': g['src_ip'],
                'dst_ip': latest_log['dst_ip'],
                'dst_port': latest_log['dst_port'],
                'dst_ports': dst_ports,
                'protocol': latest_log['protocol'],
                'prediction': latest_log['prediction'],
                'attack_types': attack_types,
                'confidence': latest_log['confidence'],
                'avg_confidence': round(g['avg_confidence'], 4) if g['avg_confidence'] else 0,
                'timestamp': g['latest'].isoformat() if g['latest'] else None,
                'earliest': g['earliest'].isoformat() if g['earliest'] else None,
                'count': g['count'],
                'features': latest_log['features'],
                'llm_analyzed': latest_log['llm_analyzed'],
                'llm_result': latest_log['llm_result'],
                'attack_type': latest_log['attack_type'],
                'acknowledged': latest_log['acknowledged'],
                'acknowledged_at': latest_log['acknowledged_at'],
                'severity': _get_severity(attack_types),
                'message': f"{len(attack_types)} attack type(s) from {g['src_ip']} targeting port(s) {', '.join(str(p) for p in dst_ports[:5])}",
            })
    
    return Response(result)


def _get_severity(attack_types):
    """Determine severity from attack type list."""
    types_lower = ' '.join(t.lower() for t in attack_types)
    if any(w in types_lower for w in ['ddos', 'dos', 'hulk', 'slowloris', 'goldeneye']):
        return 'Critical'
    if any(w in types_lower for w in ['bot', 'llm', 'sql', 'exfil', 'backdoor', 'reverse', 'shell']):
        return 'High'
    if any(w in types_lower for w in ['brute', 'scan', 'ssh', 'ftp']):
        return 'Medium'
    return 'Low'


@api_view(['GET'])
@jwt_required
def get_traffic_logs(request):
    """Get recent traffic logs with optional filtering"""
    limit = int(request.GET.get('limit', 100))
    status_filter = request.GET.get('status', None)
    
    queryset = TrafficLog.objects.all().order_by('-timestamp')
    queryset = _apply_period_filter(queryset, request)
    
    if status_filter:
        queryset = queryset.filter(status=status_filter)
    
    logs = queryset[:limit]
    serializer = TrafficLogSerializer(logs, many=True)
    return Response(serializer.data)


@api_view(['GET'])
@jwt_required
def get_diverse_alerts(request):
    """
    Get recent threats diversified by attack type.
    Strategy: pull the most recent N threat rows (Attack + Suspicious),
    then keep up to `per_type` per distinct prediction. Fast on large tables
    because it scans only the newest window, using the timestamp index.
    """
    try:
        per_type = int(request.GET.get('per_type', 5))
    except (TypeError, ValueError):
        per_type = 5

    # Cap the scan window so this stays O(window) even on 3M+ row tables.
    # 2000 newest threat rows is plenty to diversify across attack types.
    SCAN_WINDOW = 2000

    recent_threats = list(
        TrafficLog.objects
        .filter(Q(status='Attack') | Q(status='Suspicious'))
        .order_by('-timestamp')
        .values('id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'prediction', 'confidence', 'status', 'attack_type',
                'llm_analyzed', 'llm_result', 'acknowledged', 'acknowledged_at',
                'features', 'is_zero_day')
        [:SCAN_WINDOW]
    )

    # Bucket by prediction, keep the newest `per_type` per bucket
    per_pred_count = {}
    all_alerts = []
    for row in recent_threats:
        pred = row.get('prediction') or 'Unknown'
        if per_pred_count.get(pred, 0) >= per_type:
            continue
        per_pred_count[pred] = per_pred_count.get(pred, 0) + 1
        all_alerts.append(row)

    logger.info(
        "diverse-alerts: scanned=%d kept=%d distinct_preds=%d",
        len(recent_threats), len(all_alerts), len(per_pred_count)
    )
    return Response(all_alerts)


@api_view(['GET'])
@jwt_required
def get_alerts(request):
    """Get unresolved system alerts"""
    alerts = SystemAlert.objects.filter(resolved=False).order_by('-timestamp')
    serializer = SystemAlertSerializer(alerts, many=True)
    return Response(serializer.data)


def _apply_period_filter(queryset, request):
    """Apply time period filter from ?period= query param."""
    period = request.GET.get('period', '')
    if period == 'today':
        queryset = queryset.filter(timestamp__date=datetime.now().date())
    elif period == '7d':
        queryset = queryset.filter(timestamp__gte=datetime.now() - timedelta(days=7))
    elif period == '30d':
        queryset = queryset.filter(timestamp__gte=datetime.now() - timedelta(days=30))
    return queryset


@api_view(['GET'])
@jwt_required
def get_stats(request):
    """Get dashboard statistics with caching for performance."""
    from django.core.cache import cache
    
    period = request.GET.get('period', '')
    cache_key = f'pids_stats_{period or "all"}'
    cached = cache.get(cache_key)
    if cached:
        return Response(cached)
    
    qs = TrafficLog.objects.all()
    qs = _apply_period_filter(qs, request)

    # Separate counts intentionally — each uses its column index (status,
    # llm_analyzed, is_zero_day), which is faster than one FILTER aggregate
    # that would force a full sequential scan. Requires the indexes to exist.
    total = qs.count()
    attacks = qs.filter(status='Attack').count()
    suspicious = qs.filter(status='Suspicious').count()
    normal = qs.filter(status='Normal').count()

    attack_percentage = (attacks / total * 100) if total > 0 else 0

    # LLM Statistics - These are INCLUDED in main counts above
    # (LLM changes status from Suspicious to Attack/Normal, so they're already counted)
    llm_analyzed = qs.filter(llm_analyzed=True).count()
    llm_attacks = qs.filter(llm_analyzed=True, status='Attack').count()
    llm_normal = qs.filter(llm_analyzed=True, status='Normal').count()
    llm_suspicious = qs.filter(llm_analyzed=True, status='Suspicious').count()
    zero_day = qs.filter(is_zero_day=True).count()
    
    # Calculate what LLM contributed
    # LLM attacks are part of total attacks
    # LLM normal (cleared false positives) are part of total normal
    
    # Get hourly stats for last 24 hours
    hourly_stats = get_hourly_stats()
    
    # Sniffer status — check if new traffic logged in last 30 seconds
    from django.utils import timezone
    recent_cutoff = timezone.now() - timedelta(seconds=30)
    recent_count = TrafficLog.objects.filter(timestamp__gte=recent_cutoff).count()
    sniffer_active = recent_count > 0
    
    data = {
        'total_traffic': total,
        'attacks': attacks,
        'suspicious': suspicious,
        'normal': normal,
        'attack_percentage': attack_percentage,
        'llm_analyzed': llm_analyzed,
        'llm_attacks': llm_attacks,
        'llm_normal': llm_normal,
        'llm_suspicious': llm_suspicious,
        'zero_day': zero_day,
        'hourly_stats': hourly_stats,
        'sniffer_active': sniffer_active,
        'sniffer_pps': recent_count,
    }
    cache.set(cache_key, data, 10)  # Cache for 10 seconds
    return Response(data)


@api_view(['GET'])
@jwt_required
def get_protocol_stats(request):
    """Get protocol distribution"""
    protocol_stats = TrafficLog.objects.values('protocol').annotate(
        count=Count('id'),
        attacks=Count('id', filter=Q(status='Attack')),
        normal=Count('id', filter=Q(status='Normal'))
    ).order_by('-count')
    
    return Response(list(protocol_stats))


@api_view(['GET'])
@jwt_required
def get_top_ips(request):
    """Get top source IPs by activity"""
    top_src_ips = TrafficLog.objects.values('src_ip').annotate(
        count=Count('id'),
        attacks=Count('id', filter=Q(status='Attack'))
    ).order_by('-count')[:10]
    
    top_dst_ips = TrafficLog.objects.values('dst_ip').annotate(
        count=Count('id'),
        attacks=Count('id', filter=Q(status='Attack'))
    ).order_by('-count')[:10]
    
    return Response({
        'source_ips': list(top_src_ips),
        'destination_ips': list(top_dst_ips)
    })


@api_view(['GET'])
@jwt_required
def get_attack_types(request):
    """Get breakdown of attack types with optional time filter"""
    qs = TrafficLog.objects.filter(status='Attack')
    qs = _apply_period_filter(qs, request)
    # Return ALL distinct attack types (capped high). The previous [:15] cut
    # off smaller types — so on "All Time" the specific LLM/zero-day types fell
    # outside the top 15 and the LLM category showed nothing, while "7 Days"
    # (fewer types) happened to include them. The Attacks page only renders the
    # top 12 in the distribution grid but needs ALL types for category counts.
    attack_stats = qs.values('prediction').annotate(
        count=Count('id')
    ).order_by('-count')[:200]
    return Response(list(attack_stats))


@api_view(['GET'])
@jwt_required
def get_traffic_count(request):
    """Get total traffic count for export dialog"""
    total = TrafficLog.objects.count()
    attacks = TrafficLog.objects.filter(status='Attack').count()
    suspicious = TrafficLog.objects.filter(status='Suspicious').count()
    normal = TrafficLog.objects.filter(status='Normal').count()
    
    return Response({
        'total': total,
        'attacks': attacks,
        'suspicious': suspicious,
        'normal': normal
    })


# =============================================================================
# REPORT ENDPOINTS
# =============================================================================

@api_view(['GET'])
@jwt_required
def download_report(request):
    """Download CSV report (legacy endpoint)"""
    from .management.commands.pids_core.report_service import get_report_service
    
    # Get traffic logs
    logs = TrafficLog.objects.all().order_by('-timestamp')[:5000]
    
    # Generate CSV
    report_service = get_report_service()
    csv_content = report_service.generate_csv_report(logs)
    
    # Create response
    response = HttpResponse(csv_content, content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="pids_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    return response


@api_view(['GET'])
@jwt_required
def download_csv_report(request):
    """Download CSV report"""
    from .management.commands.pids_core.report_service import get_report_service
    
    limit = request.GET.get('limit', '1000')
    if limit == 'all':
        limit = 10000  # Cap at 10k to prevent memory issues
    else:
        try:
            limit = min(int(limit), 10000)
        except ValueError:
            limit = 1000
    
    logs = TrafficLog.objects.all().order_by('-timestamp').only(
        'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'protocol', 'prediction', 'confidence', 'status', 'attack_type', 'llm_analyzed',
        'features'
    )[:limit]
    
    # Generate CSV with all 31 features
    report_service = get_report_service()
    csv_content = report_service.generate_csv_report_with_features(logs)
    
    # Create response
    response = HttpResponse(csv_content, content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="pids_training_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    return response


@api_view(['GET'])
@jwt_required
def download_pdf_report(request):
    """
    Download PDF security report with AI summary.

    Query params
    ------------
    rows : int (5..200, default 20)
        Scope of the report. The WHOLE report (stats, attack-type
        breakdown, top attackers, top ports, Recent Incidents table)
        is computed from the most recent ``rows`` TrafficLog events.
        Smaller = focused snapshot of recent activity; larger = wider
        analytical window.
    """
    import traceback
    from .management.commands.pids_core.report_service import get_report_service

    try:
        # User-chosen scope for the entire report. Accepts a number or 'all'.
        # The report is computed from the most-recent `rows` events. The report
        # service aggregates the window in the DB, so there's no memory cap —
        # we only clamp to the number of rows that actually exist.
        total_rows = TrafficLog.objects.count()
        raw_rows = request.GET.get('rows', 20)
        if str(raw_rows).strip().lower() == 'all':
            rows = total_rows
        else:
            try:
                rows = int(raw_rows)
            except (TypeError, ValueError):
                rows = 20
        rows = max(5, min(rows, max(total_rows, 5)))  # honour the exact choice, up to what exists

        # generate_pdf_report builds ALL stats itself from `report_window`
        # (see _fetch_report_data), so pass None and let it scope to the window.
        report_service = get_report_service()
        pdf_buffer = report_service.generate_pdf_report(
            None, None, report_window=rows,
        )

        # Be defensive: some BytesIO paths may leave the cursor at end-of-stream
        try:
            pdf_buffer.seek(0)
        except Exception:
            pass
        pdf_bytes = pdf_buffer.read()

        if not pdf_bytes:
            raise ValueError("PDF generation returned 0 bytes")

        response = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = (
            f'attachment; filename="PIDS_Security_Report_'
            f'{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
        )
        response['Content-Length'] = str(len(pdf_bytes))
        return response

    except Exception as e:
        tb = traceback.format_exc()
        logger.error("PDF report generation failed: %s\n%s", e, tb)
        return JsonResponse(
            {'error': 'PDF generation failed', 'detail': str(e), 'type': type(e).__name__},
            status=500,
        )


@api_view(['GET'])
@jwt_required
def download_json_report(request):
    """Download JSON report"""
    from .management.commands.pids_core.report_service import get_report_service
    
    limit = request.GET.get('limit', '1000')
    if limit == 'all':
        limit = 10000
    else:
        try:
            limit = min(int(limit), 10000)
        except ValueError:
            limit = 1000
    
    logs = TrafficLog.objects.all().order_by('-timestamp').only(
        'timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
        'protocol', 'prediction', 'confidence', 'status', 'attack_type', 'llm_analyzed',
        'features', 'llm_result'
    )[:limit]
    
    stats = {
        'total_traffic': TrafficLog.objects.count(),
        'attacks': TrafficLog.objects.filter(status='Attack').count(),
        'suspicious': TrafficLog.objects.filter(status='Suspicious').count(),
        'normal': TrafficLog.objects.filter(status='Normal').count(),
    }
    
    # Generate JSON with all features
    report_service = get_report_service()
    json_content = report_service.generate_json_report_with_features(logs, stats)
    
    # Create response
    response = HttpResponse(json_content, content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="pids_training_data_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'
    
    return response


@api_view(['GET'])
@jwt_required
def get_report_preview(request):
    """Get report preview data (for dashboard)"""
    from .management.commands.pids_core.report_service import get_report_service
    
    # Get stats
    total = TrafficLog.objects.count()
    stats = {
        'total_traffic': total,
        'attacks': TrafficLog.objects.filter(status='Attack').count(),
        'suspicious': TrafficLog.objects.filter(status='Suspicious').count(),
        'normal': TrafficLog.objects.filter(status='Normal').count(),
    }
    
    # Get attack breakdown
    attack_types = TrafficLog.objects.filter(
        status='Attack'
    ).values('prediction').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Get top attackers
    top_attackers = TrafficLog.objects.filter(
        status='Attack'
    ).values('src_ip').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Generate AI summary
    report_service = get_report_service()
    logs = TrafficLog.objects.filter(status='Attack').order_by('-timestamp')[:100]
    summary = report_service._generate_ai_summary(stats, logs)
    
    return Response({
        'stats': stats,
        'attack_types': list(attack_types),
        'top_attackers': list(top_attackers),
        'summary': summary,
        'generated_at': datetime.now().isoformat()
    })


# =============================================================================
# LLM ANALYSIS ENDPOINT
# =============================================================================

@api_view(['POST'])
@jwt_required
def analyze_traffic_llm(request):
    """Analyze specific traffic with LLM"""
    from .management.commands.pids_core.llm_service import get_llm_service
    
    traffic_id = request.data.get('traffic_id')
    
    if not traffic_id:
        return Response({'error': 'traffic_id required'}, status=400)
    
    try:
        log = TrafficLog.objects.get(id=traffic_id)
    except TrafficLog.DoesNotExist:
        return Response({'error': 'Traffic log not found'}, status=404)
    
    # Get LLM service
    llm = get_llm_service()
    
    if not llm or not llm.is_available:
        return Response({'error': 'LLM service not available'}, status=503)
    
    # Prepare traffic data
    traffic_data = {
        'src_ip': log.src_ip,
        'dst_ip': log.dst_ip,
        'src_port': log.src_port,
        'dst_port': log.dst_port,
        'protocol': log.protocol,
        'ml_prediction': log.prediction,
        'ml_confidence': log.confidence
    }
    
    # Prepare features
    features = {
        'Dst Port': log.dst_port or 0,
        'Flow Duration': getattr(log, 'flow_duration', 0) or 0,
        'Fwd Pkts/s': 0,
        'Bwd Pkts/s': 0,
    }
    
    # Analyze
    result = llm.analyze_zero_day(traffic_data, features)
    
    return Response({
        'traffic_id': traffic_id,
        'analysis': result,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# ALERT ENDPOINTS
# =============================================================================

@api_view(['POST'])
@jwt_required
def clear_alerts(request):
    """Mark all alerts as resolved"""
    SystemAlert.objects.filter(resolved=False).update(resolved=True)
    return Response({'status': 'success', 'message': 'All alerts cleared'})


@api_view(['POST'])
@jwt_required
def create_alert(request):
    """Create a new system alert"""
    try:
        data = request.data
        alert = SystemAlert.objects.create(
            severity=data.get('severity', 'MEDIUM'),
            message=data.get('message', ''),
            resolved=False
        )
        serializer = SystemAlertSerializer(alert)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@jwt_required
def clear_traffic_logs(request):
    """Clear all traffic logs (for testing)"""
    if request.method == 'DELETE':
        count = TrafficLog.objects.all().delete()[0]
        return Response({'status': 'success', 'deleted_count': count})
    return Response({'error': 'Method not allowed'}, status=405)


@api_view(['DELETE'])
@jwt_required
def delete_traffic_log(request, log_id):
    """Delete a single traffic log (false positive removal)"""
    try:
        log = TrafficLog.objects.get(id=log_id)
        log.delete()
        return Response({'status': 'success', 'message': f'Traffic log {log_id} deleted'})
    except TrafficLog.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)


@api_view(['PUT'])
@jwt_required
def acknowledge_traffic_log(request, log_id):
    """Acknowledge a traffic log alert (analyst has seen it)."""
    try:
        log = TrafficLog.objects.get(id=log_id)
        from django.utils import timezone
        log.acknowledged = True
        log.acknowledged_at = timezone.now()
        log.save()
        return Response({
            'status': 'success',
            'message': f'Alert #{log_id} acknowledged',
            'acknowledged_at': log.acknowledged_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    except TrafficLog.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)


@api_view(['PUT'])
@jwt_required
def reclassify_traffic_log(request, log_id):
    """Reclassify a traffic log as Normal (false positive correction)"""
    try:
        log = TrafficLog.objects.get(id=log_id)
        log.status = 'Normal'
        log.prediction = 'Normal'
        log.confidence = 0.99
        log.attack_type = None
        log.save()
        return Response({'status': 'success', 'message': f'Traffic log {log_id} reclassified as Normal'})
    except TrafficLog.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)


@api_view(['GET'])
@jwt_required
def get_traffic_features(request, log_id):
    """Get features for a single traffic log — called when user expands alert."""
    try:
        log = TrafficLog.objects.only('features').get(id=log_id)
        return Response({'features': log.features})
    except TrafficLog.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)


@api_view(['POST'])
@jwt_required
def recheck_with_llm(request, log_id):
    """
    Re-analyse a traffic log with the LLM and persist the new verdict.

    Two operating modes (selected by ``settings.LLM_RECHECK_MODE``):

    * ``'pure'`` (default) — the LLM is the sole decision-maker. All
      heuristic short-circuits (multicast clearing, rate-detection
      preservation, malicious-port preservation, post-LLM feature
      override) are skipped. The flow's contextual signals are
      packaged into the prompt as annotations the LLM weighs itself,
      not as Python branches.
    * ``'hybrid'`` — keeps the legacy heuristic gates around the LLM
      call. Useful as a fallback if the LLM proves unreliable for a
      specific deployment.
    """
    try:
        log = TrafficLog.objects.get(id=log_id)
    except TrafficLog.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    if not log.features:
        return Response({'error': 'No features available for this traffic log'}, status=400)

    from django.conf import settings as dj_settings
    mode = (request.data.get('mode') if hasattr(request, 'data') else None) \
           or getattr(dj_settings, 'LLM_RECHECK_MODE', 'pure')
    mode = mode if mode in ('pure', 'hybrid') else 'pure'

    try:
        # =================================================================
        # PURE MODE — every recheck goes straight to Llama, no heuristics.
        # =================================================================
        if mode == 'pure':
            from api.management.commands.pids_core.llm_service import get_llm_service
            llm = get_llm_service()
            if not llm or not llm.is_available:
                return Response({'error': 'LLM service not available'}, status=503)

            log_info = {
                'src_ip': log.src_ip, 'dst_ip': log.dst_ip,
                'src_port': log.src_port, 'dst_port': log.dst_port,
                'protocol': log.protocol,
                'ml_prediction': log.prediction,
                'ml_confidence': log.confidence,
                'original_status': log.status,
            }
            verdict = llm.comprehensive_recheck(log_info, log.features)

            if not verdict.get('success'):
                return Response({
                    'error': f"LLM recheck failed: {verdict.get('error', 'unknown')}",
                    'llm_raw': verdict.get('llm_raw'),
                }, status=503)

            attack_category = verdict.get('attack_category', 'Unknown')
            llm_conf = verdict.get('confidence', 0.7)
            reasoning = verdict.get('reasoning', '')
            is_attack = bool(verdict.get('is_attack'))

            # ─── GUARDRAIL: protect high-confidence rate-based ML verdicts ───
            # Small LLMs (Llama 3.2:1b) over-confidently downgrade DoS / DDoS /
            # brute-force detections because per-flow features look "normal"
            # even though the rate itself is the attack signature. Require
            # OVERWHELMING LLM confidence (>= 0.92) before clobbering a
            # high-confidence (>= 0.85) ML rate-based verdict.
            ml_pred_lower = (log.prediction or '').lower()
            ml_was_rate_attack = any(kw in ml_pred_lower for kw in
                ('brute', 'flood', 'loic', 'hoic', 'ddos', 'dos', 'hulk',
                 'goldeneye', 'slowloris', 'slowhttp'))
            ml_was_high_conf  = (log.confidence or 0) >= 0.85
            llm_says_benign   = (not is_attack) or attack_category.lower() in ('normal', 'benign', 'none', '')
            guardrail_blocked = (ml_was_rate_attack and ml_was_high_conf
                                 and llm_says_benign and llm_conf < 0.92)
            if guardrail_blocked:
                # Keep ML verdict; record that the LLM disagreed but was overruled.
                log.llm_analyzed = True
                log.llm_result = json.dumps({
                    'reasoning': (
                        f"LLM proposed '{attack_category}' ({llm_conf:.0%}) but was "
                        f"overruled: ML rate-based verdict '{log.prediction}' "
                        f"({(log.confidence or 0):.0%}) protected by guardrail. "
                        f"LLM reasoning: {reasoning}"
                    ),
                    'attack_category': log.prediction,
                    'confidence':       log.confidence,
                    'rechecked': True,
                    'mode': 'pure',
                    'guardrail_blocked': True,
                    'llm_proposed': {
                        'attack_category': attack_category,
                        'confidence':      llm_conf,
                        'reasoning':       reasoning,
                    },
                })
                log.save()
                return Response({
                    'status': 'success',
                    'mode': 'pure',
                    'new_prediction': log.prediction,
                    'new_confidence': log.confidence,
                    'new_status':     log.status,
                    'reasoning': (
                        f"LLM disagreed (proposed {attack_category} @ "
                        f"{llm_conf:.0%}) but was overruled — ML rate-based "
                        f"verdicts are protected unless the LLM has ≥92% "
                        f"confidence. Original verdict preserved."
                    ),
                    'attack_category': log.prediction,
                    'guardrail': True,
                })

            log.llm_analyzed = True
            log.llm_result = json.dumps({
                'reasoning': reasoning,
                'attack_category': attack_category,
                'confidence': llm_conf,
                'rechecked': True,
                'mode': 'pure',
                'independent': True,
            })

            if is_attack and attack_category.lower() not in ('normal', 'benign', 'none', ''):
                log.prediction = f"LLM-Detected: {attack_category}"
                log.confidence = llm_conf
                log.status = 'Attack'
                log.attack_type = attack_category
            else:
                log.prediction = 'Normal'
                log.confidence = max(llm_conf, 0.85)
                log.status = 'Normal'
                log.attack_type = None
            log.save()

            return Response({
                'status': 'success',
                'mode': 'pure',
                'new_prediction': log.prediction,
                'new_confidence': log.confidence,
                'new_status': log.status,
                'reasoning': reasoning,
                'attack_category': attack_category,
            })

        # =================================================================
        # HYBRID MODE — legacy path, kept for backward-compatibility.
        # Identical to the pre-Item-E behaviour.
        # =================================================================
        # ─── PRE-CHECK: Multicast / Broadcast / mDNS — instant false-positive clear ───
        benign_multicast_ports = {5353, 1900, 5355, 547, 546}
        benign_broadcast_ports = {137, 138, 139, 67, 68, 1900}
        dst_ip = log.dst_ip or ''
        dst_port = log.dst_port or 0

        is_multicast = dst_ip.startswith(('224.', '225.', '226.', '227.',
                                          '228.', '229.', '230.', '231.',
                                          '232.', '233.', '234.', '235.',
                                          '236.', '237.', '238.', '239.'))
        is_broadcast = dst_ip == '255.255.255.255' or dst_ip.endswith('.255')

        if (is_multicast and dst_port in benign_multicast_ports) or \
           (is_broadcast and dst_port in benign_broadcast_ports):
            # This is benign network discovery — clear to Normal immediately
            protocol_names = {5353: 'mDNS', 1900: 'SSDP', 5355: 'LLMNR',
                              137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
                              67: 'DHCP', 68: 'DHCP', 547: 'DHCPv6', 546: 'DHCPv6'}
            proto_name = protocol_names.get(dst_port, 'Network Discovery')
            reasoning = (f"Normal {proto_name} traffic — "
                         f"{'multicast' if is_multicast else 'broadcast'} "
                         f"to {dst_ip}:{dst_port} is standard OS-level network discovery, not an attack.")
            log.llm_analyzed = True
            log.llm_result = json.dumps({
                'reasoning': reasoning,
                'attack_category': 'Normal',
                'confidence': 0.99,
                'rechecked': True,
                'cleared_as': proto_name,
            })
            log.prediction = 'Normal'
            log.confidence = 0.99
            log.status = 'Normal'
            log.attack_type = None
            log.save()
            return Response({
                'status': 'success',
                'new_prediction': 'Normal',
                'new_confidence': 0.99,
                'new_status': 'Normal',
                'reasoning': reasoning,
                'attack_category': 'Normal',
            })

        # ─── PRE-CHECK: Rate-detected attacks — LLM can't assess connection rates ───
        auth_ports = {22, 23, 21, 3389, 1433, 3306, 5432, 445}
        mal_ports = {4444, 1337, 31337, 5555, 4443, 1234, 12345, 6667, 9001, 2375, 6379, 27017}
        current_pred = (log.prediction or '').lower()
        src_port = log.src_port or 0
        
        is_rate_detection = any(kw in current_pred for kw in ['brute', 'flood', 'loic', 'hoic', 'ddos', 'dos'])
        is_mal_port = (dst_port in mal_ports or src_port in mal_ports)
        
        if is_rate_detection and (dst_port in auth_ports or src_port in auth_ports):
            reasoning = (f"This attack was detected by connection rate analysis — {log.prediction} on port "
                         f"{dst_port}. The LLM cannot assess connection rates from a single packet, "
                         f"so rate-based detections are preserved. The high connection rate to this "
                         f"authentication port is the primary indicator of brute force activity.")
            return Response({
                'status': 'success',
                'new_prediction': log.prediction,
                'new_confidence': log.confidence,
                'new_status': 'Attack',
                'reasoning': reasoning,
                'attack_category': log.prediction,
            })
        
        if is_mal_port and log.status == 'Attack':
            mal_names = {4444: 'Metasploit', 1337: 'Backdoor', 6667: 'IRC C2', 31337: 'Back Orifice'}
            port_name = mal_names.get(dst_port) or mal_names.get(src_port) or 'known malicious'
            reasoning = (f"Port {dst_port or src_port} ({port_name}) is a known malicious port. "
                         f"Local traffic on this port indicates {log.prediction}. "
                         f"Malicious port detections are preserved as the port itself is the primary indicator.")
            return Response({
                'status': 'success',
                'new_prediction': log.prediction,
                'new_confidence': log.confidence,
                'new_status': 'Attack',
                'reasoning': reasoning,
                'attack_category': log.prediction,
            })

        # ─── Normal LLM recheck path — INDEPENDENT analysis (no ML bias) ───
        from api.management.commands.pids_core.llm_service import get_llm_service
        llm = get_llm_service()
        if not llm or not llm.is_available:
            return Response({'error': 'LLM service not available'}, status=503)

        # Don't send ML prediction to LLM — let it analyze independently
        traffic_data = {
            'src_ip': log.src_ip, 'dst_ip': log.dst_ip,
            'src_port': log.src_port, 'dst_port': log.dst_port,
            'protocol': log.protocol,
            'ml_prediction': 'Unknown', 'ml_confidence': 0.0,
            'skip_cache': True  # Bypass LLM cache on recheck
        }

        result = llm.analyze_zero_day(traffic_data, log.features)

        if result.get('success'):
            attack_category = result.get('attack_category', 'Normal')
            llm_conf = result.get('confidence', 0.7)
            reasoning = result.get('reasoning', '')
            is_attack = result.get('is_suspicious', False) or result.get('is_zero_day', False)
            
            # FEATURE-BASED OVERRIDE: If LLM says Normal but features show clear attack,
            # override with feature-based classification (small LLMs miss obvious attacks)
            if not is_attack and log.features and isinstance(log.features, dict):
                f = log.features
                fwd_pkt_mean = f.get('Fwd Pkt Len Mean', 0) or 0
                tot_bwd = f.get('Tot Bwd Pkts', 0) or 0
                flow_duration = f.get('Flow Duration', 0) or 0
                dst_port = f.get('Dst Port', 0) or 0
                fwd_iat_max = f.get('Fwd IAT Max', 0) or 0
                
                override_reason = None
                override_category = None
                
                # Unidirectional flood: large packets, zero backward traffic
                if fwd_pkt_mean > 500 and tot_bwd == 0 and flow_duration > 10000:
                    override_category = 'DoS attacks-Hulk'
                    override_reason = f"high fwd rate {fwd_pkt_mean:.0f}B/pkt; completely unidirectional (zero response); large flood packets ({fwd_pkt_mean:.0f}B)"
                
                # Known malicious ports
                mal_ports = {4444: 'Data Exfiltration', 1337: 'Backdoor Trojan', 
                            6667: 'Botnet C2', 31337: 'Reverse Shell'}
                if dst_port in mal_ports:
                    override_category = mal_ports[dst_port]
                    override_reason = f"traffic on exclusively malicious port {dst_port}"
                
                if override_category:
                    attack_category = override_category
                    reasoning = override_reason
                    llm_conf = 0.90
                    is_attack = True

            # Store LLM analysis result
            log.llm_analyzed = True
            log.llm_result = json.dumps({
                'reasoning': reasoning,
                'attack_category': attack_category,
                'confidence': llm_conf,
                'rechecked': True,
                'independent': True  # Flag that this was independent recheck
            })

            if is_attack and attack_category.lower() not in ('normal', 'benign', 'none', ''):
                # LLM says attack — update prediction
                log.prediction = f"LLM-Detected: {attack_category}"
                log.confidence = llm_conf
                log.status = 'Attack'
                log.attack_type = attack_category
            else:
                # LLM says Normal — trust the independent LLM analysis
                log.prediction = 'Normal'
                log.confidence = max(llm_conf, 0.85)
                log.status = 'Normal'
                log.attack_type = None

            log.save()

            return Response({
                'status': 'success',
                'new_prediction': log.prediction,
                'new_confidence': log.confidence,
                'new_status': log.status,
                'reasoning': reasoning,
                'attack_category': attack_category,
            })
        else:
            return Response({'error': 'LLM analysis failed'}, status=500)

    except Exception as e:
        return Response({'error': f'LLM recheck error: {str(e)}'}, status=500)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_hourly_stats():
    """Get hourly statistics for last 24 hours"""
    from django.utils import timezone
    hourly_stats = []
    now = timezone.now()

    # Per-hour windows use the timestamp index over a small recent range, so 24
    # light index scans here are faster than one big FILTER aggregate.
    for i in range(24):
        hour_start = now - timedelta(hours=i+1)
        hour_end = now - timedelta(hours=i)

        stats = TrafficLog.objects.filter(
            timestamp__gte=hour_start,
            timestamp__lt=hour_end
        ).aggregate(
            total=Count('id'),
            attacks=Count('id', filter=Q(status='Attack')),
            suspicious=Count('id', filter=Q(status='Suspicious'))
        )

        hourly_stats.append({
            'hour': hour_start.strftime('%H:00'),
            'total': stats['total'] or 0,
            'attacks': stats['attacks'] or 0,
            'suspicious': stats['suspicious'] or 0
        })

    return list(reversed(hourly_stats))