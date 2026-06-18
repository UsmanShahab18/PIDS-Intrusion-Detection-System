"""
PIDS - Reprocess Suspicious Traffic with LLM
Run: python manage.py reprocess_suspicious
"""
from django.core.management.base import BaseCommand
from api.models import TrafficLog
from colorama import Fore, Style, init
import time

init()  # Initialize colorama


class Command(BaseCommand):
    help = 'Reprocess all suspicious traffic with LLM to classify as Attack or Normal'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Number of suspicious entries to process (default: 100)'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Process ALL suspicious traffic'
        )

    def handle(self, *args, **options):
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔮 PIDS - Reprocess Suspicious Traffic with LLM{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        # Initialize LLM
        try:
            from api.management.commands.pids_core.llm_service import get_llm_service
            llm_service = get_llm_service()
            
            if not llm_service or not llm_service.is_available:
                print(f"{Fore.RED}❌ LLM service not available!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Make sure Ollama is running: ollama serve{Style.RESET_ALL}")
                return
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to initialize LLM: {e}{Style.RESET_ALL}")
            return
        
        # Get suspicious traffic
        if options['all']:
            suspicious = TrafficLog.objects.filter(status='Suspicious').order_by('-timestamp')
            limit_text = "ALL"
        else:
            suspicious = TrafficLog.objects.filter(status='Suspicious').order_by('-timestamp')[:options['limit']]
            limit_text = str(options['limit'])
        
        total = suspicious.count()
        print(f"📊 Found {total} suspicious entries to process (limit: {limit_text})")
        
        if total == 0:
            print(f"{Fore.GREEN}✅ No suspicious traffic to process!{Style.RESET_ALL}")
            return
        
        # Stats
        stats = {
            'processed': 0,
            'to_attack': 0,
            'to_normal': 0,
            'failed': 0
        }
        
        print(f"\n{Fore.YELLOW}Starting LLM analysis...{Style.RESET_ALL}\n")
        
        for i, log in enumerate(suspicious):
            try:
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
                
                # Get features
                features = log.features if log.features else {
                    'Dst Port': log.dst_port,
                    'Flow Duration': 1000000,
                    'Tot Fwd Pkts': 10,
                    'Tot Bwd Pkts': 5,
                }
                
                # Analyze with LLM
                result = llm_service.analyze_zero_day(traffic_data, features)
                
                if result.get('success'):
                    is_suspicious = result.get('is_suspicious', False)
                    attack_category = result.get('attack_category', '')
                    llm_conf = result.get('confidence', 0.7)
                    
                    if is_suspicious and attack_category.lower() not in ['benign', 'normal', 'none', '']:
                        # Update to Attack
                        log.status = 'Attack'
                        log.prediction = f"LLM-Detected: {attack_category}"
                        log.confidence = llm_conf
                        log.attack_type = attack_category
                        log.llm_analyzed = True
                        log.is_zero_day = True
                        log.save()
                        
                        stats['to_attack'] += 1
                        print(f"{Fore.RED}🔴 [{i+1}/{total}] → ATTACK: {attack_category}{Style.RESET_ALL}")
                    else:
                        # Update to Normal
                        log.status = 'Normal'
                        log.prediction = 'Normal'
                        log.confidence = 0.88
                        log.attack_type = None
                        log.llm_analyzed = True
                        log.is_zero_day = False
                        log.save()
                        
                        stats['to_normal'] += 1
                        print(f"{Fore.GREEN}🟢 [{i+1}/{total}] → NORMAL (Cleared){Style.RESET_ALL}")
                    
                    stats['processed'] += 1
                else:
                    stats['failed'] += 1
                    print(f"{Fore.YELLOW}⚠️ [{i+1}/{total}] Failed: {result.get('error', 'Unknown')}{Style.RESET_ALL}")
                
                # Small delay to prevent overwhelming LLM
                time.sleep(0.3)
                
            except Exception as e:
                stats['failed'] += 1
                print(f"{Fore.RED}❌ [{i+1}/{total}] Error: {e}{Style.RESET_ALL}")
        
        # Final stats
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 REPROCESSING COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"   Total Processed: {stats['processed']}")
        print(f"   🔴 Classified as Attack: {stats['to_attack']}")
        print(f"   🟢 Cleared as Normal: {stats['to_normal']}")
        print(f"   ⚠️  Failed: {stats['failed']}")
        
        # Show remaining
        remaining = TrafficLog.objects.filter(status='Suspicious').count()
        print(f"\n   📋 Remaining Suspicious: {remaining}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")