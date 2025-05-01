from typing import Dict, List, Tuple

def judge(constraint: Dict) -> Dict:
    if "desc" in constraint and constraint["desc"] == "NoRetypeCandidates":
        return None
    
    return constraint
    
