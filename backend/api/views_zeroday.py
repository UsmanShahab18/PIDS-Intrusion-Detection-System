"""
Zero-day detection API.

Endpoints
---------
* ``POST /api/zero-day/scan/`` — run the full DuckDuckGo + LLM workflow
  on user-supplied flow info; returns the step-by-step trace the
  frontend can visualise.
* ``GET  /api/zero-day/recent/`` — list TrafficLog rows previously
  flagged as zero-day candidates by the live capture pipeline.
"""
from __future__ import annotations

from rest_framework.decorators import api_view
from rest_framework.response import Response

from api.auth_utils import jwt_required


@api_view(['POST'])
@jwt_required
def scan_zero_day(request):
    """
    Run the zero-day workflow on user-provided traffic context.

    Request body
    ------------
    ``{
        "port":     int   (required, 1-65535),
        "protocol": "TCP" | "UDP"  (default "TCP"),
        "src_ip":   str   (optional, defaults to ""),
        "dst_ip":   str   (optional, defaults to ""),
        "features": dict  (optional 31-feature flow vector; defaults to {})
    }``

    Response
    --------
    Whatever ``LLMService.zero_day_scan`` returns — a dict with the
    full step trace + final verdict. See its docstring for the schema.
    """
    body = request.data or {}
    try:
        port = int(body.get('port', 0))
    except (TypeError, ValueError):
        return Response({'error': "Field 'port' must be an integer (1-65535)."}, status=400)
    if not (1 <= port <= 65535):
        return Response({'error': "Field 'port' must be in range 1-65535."}, status=400)

    protocol = (body.get('protocol') or 'TCP').upper()
    if protocol not in ('TCP', 'UDP'):
        return Response({'error': "Field 'protocol' must be 'TCP' or 'UDP'."}, status=400)

    src_ip = (body.get('src_ip') or '').strip()
    dst_ip = (body.get('dst_ip') or '').strip()
    features = body.get('features') if isinstance(body.get('features'), dict) else {}

    try:
        from api.management.commands.pids_core.llm_service import get_llm_service
        llm = get_llm_service()
    except Exception as exc:
        return Response({'error': f'LLM service unavailable: {exc}'}, status=503)

    try:
        result = llm.zero_day_scan(
            port=port, protocol=protocol,
            src_ip=src_ip, dst_ip=dst_ip,
            features=features,
        )
    except Exception as exc:
        return Response({'error': f'Scan failed: {exc}'}, status=500)

    return Response(result)


@api_view(['GET'])
@jwt_required
def recent_zero_day(request):
    """
    Return the most recent TrafficLog rows tagged as zero-day candidates
    by the live pipeline (those whose ``llm_result`` indicates the LLM
    promoted the flow to attack status).
    """
    from api.models import TrafficLog
    try:
        limit = max(1, min(100, int(request.GET.get('limit', 20))))
    except (TypeError, ValueError):
        limit = 20

    qs = (TrafficLog.objects
          .filter(llm_analyzed=True)
          .exclude(llm_result__isnull=True)
          .order_by('-timestamp')[:limit])

    rows = []
    import json as _json
    for log in qs:
        result = log.llm_result
        if isinstance(result, str):
            try:
                result = _json.loads(result)
            except Exception:
                result = {'reasoning': str(result)[:200]}
        rows.append({
            'id': log.id,
            'timestamp': log.timestamp.isoformat() if hasattr(log.timestamp, 'isoformat') else str(log.timestamp),
            'src_ip': log.src_ip, 'dst_ip': log.dst_ip,
            'src_port': log.src_port, 'dst_port': log.dst_port,
            'protocol': log.protocol,
            'prediction': log.prediction,
            'confidence': log.confidence,
            'status': log.status,
            'attack_type': getattr(log, 'attack_type', None),
            'llm_result': result,
        })
    return Response({'count': len(rows), 'rows': rows})
