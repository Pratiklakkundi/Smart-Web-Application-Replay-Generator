from typing import List, Dict, Tuple
from parser.log_parser import LogParser
from detector.attack_detector import AttackDetector
from database.db_manager import DatabaseManager

class BatchProcessor:
    def __init__(self, db_manager: DatabaseManager = None):
        self.db_manager = db_manager
        self.parser = LogParser()
    
    def process_multiple_files(self, files: List[Tuple[str, str]], enable_learning: bool = False) -> List[Dict]:
        results = []
        detector = AttackDetector(db_manager=self.db_manager, enable_learning=enable_learning)
        
        for filename, content in files:
            try:
                parsed_logs = self.parser.parse_log_file(content)
                analysis = detector.analyze_logs(parsed_logs)
                
                total_lines = len(content.split('\n'))
                
                if self.db_manager:
                    try:
                        analysis_id = self.db_manager.save_analysis(
                            filename=filename,
                            total_lines=total_lines,
                            total_attacks=analysis.get('total_attacks', 0),
                            unique_ips=analysis.get('unique_ips', 0),
                            attack_breakdown=analysis.get('attack_type_counts', {}),
                            attacks_data=analysis.get('attacks', [])
                        )
                        analysis['analysis_id'] = analysis_id
                    except Exception:
                        pass
                
                results.append({
                    'filename': filename,
                    'success': True,
                    'total_lines': total_lines,
                    'parsed_lines': len(parsed_logs),
                    'analysis': analysis,
                    'error': None
                })
            except Exception as e:
                results.append({
                    'filename': filename,
                    'success': False,
                    'error': str(e),
                    'analysis': None
                })
        
        return results
    
    def get_batch_summary(self, results: List[Dict]) -> Dict:
        total_files = len(results)
        successful = sum(1 for r in results if r['success'])
        failed = total_files - successful
        
        total_attacks = 0
        total_lines = 0
        all_attack_types = {}
        unique_ips = set()
        
        for result in results:
            if result['success'] and result['analysis']:
                analysis = result['analysis']
                total_attacks += analysis.get('total_attacks', 0)
                total_lines += result.get('total_lines', 0)
                
                for attack_type, count in analysis.get('attack_type_counts', {}).items():
                    all_attack_types[attack_type] = all_attack_types.get(attack_type, 0) + count
                
                for ip in analysis.get('ip_attacks', {}).keys():
                    unique_ips.add(ip)
        
        return {
            'total_files': total_files,
            'successful': successful,
            'failed': failed,
            'total_attacks': total_attacks,
            'total_lines': total_lines,
            'attack_type_counts': all_attack_types,
            'unique_ips': len(unique_ips)
        }
