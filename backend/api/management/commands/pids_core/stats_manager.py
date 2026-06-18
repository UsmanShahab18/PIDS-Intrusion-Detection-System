"""
PIDS - Statistics Manager
Tracks traffic statistics including LLM analysis results
"""
from datetime import datetime
from colorama import Fore, Style


class StatsManager:
    def __init__(self):
        self.stats = {
            'total': 0, 
            'normal': 0, 
            'attack': 0, 
            'suspicious': 0,
            # LLM-specific stats
            'llm_analyzed': 0,
            'llm_to_attack': 0,      # Suspicious → Attack (LLM found threat)
            'llm_to_normal': 0,      # Suspicious → Normal (LLM cleared as false positive)
            'llm_confirmed': 0,      # LLM confirmed suspicious
            'zero_day_detected': 0,
            'start_time': datetime.now()
        }

    def update(self, status):
        """Update basic traffic counts"""
        self.stats['total'] += 1
        if status == 'Attack':
            self.stats['attack'] += 1
        elif status == 'Suspicious':
            self.stats['suspicious'] += 1
        else:
            self.stats['normal'] += 1
    
    def update_llm_result(self, original_status, new_status, is_zero_day=False):
        """
        Track LLM analysis results
        
        Args:
            original_status: Status before LLM ('Suspicious')
            new_status: Status after LLM ('Attack' or 'Normal')
            is_zero_day: Whether LLM detected a zero-day attack
        """
        self.stats['llm_analyzed'] += 1
        
        if original_status == 'Suspicious':
            if new_status == 'Attack':
                self.stats['llm_to_attack'] += 1
                if is_zero_day:
                    self.stats['zero_day_detected'] += 1
            elif new_status == 'Normal':
                self.stats['llm_to_normal'] += 1
            else:
                self.stats['llm_confirmed'] += 1

    def show_final_stats(self):
        """Display comprehensive final statistics"""
        duration = datetime.now() - self.stats['start_time']
        total = max(self.stats['total'], 1)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 PIDS SESSION STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Basic Stats
        print(f"\n{Fore.WHITE}📦 Traffic Overview:{Style.RESET_ALL}")
        print(f"   Total Packets:      {self.stats['total']:,}")
        print(f"   🟢 Normal:          {self.stats['normal']:,} ({self.stats['normal']/total*100:.1f}%)")
        print(f"   🟡 Suspicious:      {self.stats['suspicious']:,} ({self.stats['suspicious']/total*100:.1f}%)")
        print(f"   🔴 Attacks:         {self.stats['attack']:,} ({self.stats['attack']/total*100:.1f}%)")
        
        # LLM Stats
        if self.stats['llm_analyzed'] > 0:
            print(f"\n{Fore.MAGENTA}🔮 LLM Analysis Results:{Style.RESET_ALL}")
            print(f"   Total Analyzed:     {self.stats['llm_analyzed']:,}")
            print(f"   → Classified Attack:{self.stats['llm_to_attack']:,}")
            print(f"   → Cleared as Normal:{self.stats['llm_to_normal']:,}")
            print(f"   → Remained Suspect: {self.stats['llm_confirmed']:,}")
            print(f"   🆕 Zero-Day Found:  {self.stats['zero_day_detected']:,}")
        
        # Session Info
        print(f"\n{Fore.WHITE}⏱️  Session Duration: {duration}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def get_stats(self):
        """Get stats dictionary for API"""
        return {
            'total_traffic': self.stats['total'],
            'normal': self.stats['normal'],
            'suspicious': self.stats['suspicious'],
            'attacks': self.stats['attack'],
            'llm_analyzed': self.stats['llm_analyzed'],
            'llm_attacks': self.stats['llm_to_attack'],
            'llm_cleared': self.stats['llm_to_normal'],
            'zero_day': self.stats['zero_day_detected']
        }