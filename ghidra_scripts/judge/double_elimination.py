from typing import List, Optional, Dict, Deque, Set
from collections import deque
import random

class Player:
    def __init__(self, name: str):
        self.name = name
        self.bracket = "winners"  # can be "winners", "losers", "eliminated" or "champion"

    def __repr__(self):
        return f"Player({self.name}, bracket={self.bracket})"
    
    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, Player):
            return self.name == other.name
        return False
    

class Match:
    def __init__(self, player1: Player, player2: Player, type: str, level: Optional[int] = None):
        self.player1 = player1
        self.player2 = player2
        # There are three types of matches: winners, losers, and finals
        self.type = type
        self.winner = None
        self.loser = None
        self.level = level

    def judge(self):
        # Randomly select a winner instead of always picking player1
        self.winner = random.choice([self.player1, self.player2])
        self.loser = self.player1 if self.winner == self.player2 else self.player2
    
    def get_winner(self) -> Player:
        return self.winner
    
    def get_loser(self) -> Player:
        return self.loser
    
    def __repr__(self):
        if self.level is not None:
            return f"Match({self.type} @ {self.level}: {self.player1} vs {self.player2})"
        else:
            return f"Match({self.type}: {self.player1} vs {self.player2})"


class DoubleEliminationTournament:

    def __init__(self, players: List[Player]):
        self.players = players

        self.winners_level = 0 # The level of the winners bracket ready to be judged
        self.losers_level = 0 # The level of the losers bracket ready to be judged
        self.winners_bracket: Dict[int, Set[Player]] = {}
        self.losers_bracket: Dict[int, Set[Player]] = {}
        self.eliminated = []

        self.ready_matches: List[Match] = []
        self.is_final = False
        self.champion = None
    
    def create_initial_matches(self) -> List[Match]:
        """
        Create the initial matches for the tournament.
        Each match is a pair of players.
        """
        if len(self.players) % 2 != 0:
            bye_player = random.choice(self.players)
            self.players.remove(bye_player)
            
            self.winners_bracket.setdefault(self.winners_level + 1, set()).add(bye_player)

        for i in range(0, len(self.players), 2):
            p1 = self.players[i]
            p2 = self.players[i + 1]
            self.winners_bracket.setdefault(self.winners_level, set()).add(p1)
            self.winners_bracket.setdefault(self.winners_level, set()).add(p2)

            match = Match(p1, p2, "winners", self.winners_level)
            self.ready_matches.append(match)

    def get_ready_matches(self) -> List[Match]:
        """
        Get the matches that are ready to be judged.
        """
        return self.ready_matches
    
    def process_results(self):
        """
        Process the results of the matches and prepare for the next round of ready matches.
        """
        handled_winners = False
        handled_losers = False

        for match in self.ready_matches:
            if match.type == "winners":
                handled_winners = True
            if match.type == "losers":
                handled_losers = True
        if handled_winners:
            self.winners_level += 1
        if handled_losers:
            self.losers_level += 1

        for match in self.ready_matches:
            # handle the winners
            if match.type == "winners":
                winner = match.get_winner()
                loser = match.get_loser()
                
                self.winners_bracket.setdefault(self.winners_level, set()).add(winner)
                self.losers_bracket.setdefault(self.losers_level, set()).add(loser)
                loser.bracket = "losers"
            
            # handle the losers
            if match.type == "losers":
                winner = match.get_winner()
                loser = match.get_loser()

                self.losers_bracket.setdefault(self.losers_level, set()).add(winner)
                self.eliminated.append(loser)
                loser.bracket = "eliminated"

            # handle the finals
            if match.type == "finals":
                winner = match.get_winner()
                loser = match.get_loser()
                self.champion = winner
                self.eliminated.append(loser)
                winner.bracket = "champion"
                loser.bracket = "eliminated"

        self.prepare_next_round()

    def prepare_next_round(self):
        """
        Prepare the next round of matches.
        This function should be called after all matches in the current round are judged.
        """
        # empty the ready matches
        self.ready_matches = []

        # handle the winners bracket
        current_winners = list(self.winners_bracket.get(self.winners_level))

        if len(current_winners) % 2 != 0 and len(current_winners) > 1:
            bye_player = random.choice(list(current_winners))
            current_winners.remove(bye_player)
            self.winners_bracket.setdefault(self.winners_level + 1, set()).add(bye_player)
        
        if len(current_winners) > 1:
            for i in range(0, len(current_winners), 2):
                p1 = current_winners[i]
                p2 = current_winners[i + 1]
                match = Match(p1, p2, "winners", self.winners_level)
                self.ready_matches.append(match)

        # handle the losers bracket
        current_losers = list(self.losers_bracket.get(self.losers_level))

        if len(current_losers) % 2 != 0 and len(current_losers) > 1:
            bye_player = random.choice(list(current_losers))
            current_losers.remove(bye_player)
            self.losers_bracket.setdefault(self.losers_level + 1, set()).add(bye_player)
        
        if len(current_losers) > 1:
            for i in range(0, len(current_losers), 2):
                p1 = current_losers[i]
                p2 = current_losers[i + 1]
                match = Match(p1, p2, "losers", self.losers_level)
                self.ready_matches.append(match)
        
        # handle the finals
        if len(current_winners) == 1 and len(current_losers) == 1:
            self.is_final = True
            winner = list(current_winners)[0]
            loser = list(current_losers)[0]
            match = Match(winner, loser, "finals")
            self.ready_matches.append(match)

        if self.champion is not None:
            self.ready_matches = []

    def get_winners_bracket(self) -> Dict[int, Set[Player]]:
        return self.winners_bracket
    
    def get_losers_bracket(self) -> Dict[int, Set[Player]]:
        return self.losers_bracket

    def get_champion(self) -> Player:
        return self.champion
    

def run(constraint: Dict) -> Dict:
    if "desc" in constraint and constraint["desc"] == "NoRetypeCandidates":
        return None
    
    """
        "ForgedStruct_123" : {
        "desc" : "Structure",
        "layout" : {
            "0x0" : {
            "desc" : "Primitive",
            "size" : 4,
            "type" : "int",
            "name" : "field_0x0"
            },
            "0x4" : {
            "desc" : "Primitive",
            "size" : 4,
            "type" : "uint",
            "name" : "field_0x4"
            },
            "0x8" : {
            "desc" : "Primitive",
            "size" : 4,
            "type" : "uint",
            "name" : "field_0x8"
            },
            "0xc" : {
            "desc" : "Primitive",
            "size" : 4,
            "type" : "uint",
            "name" : "field_0xc"
            }
        },
        "ptrRef" : { },
        "nest" : { },
        "anonTypes" : { },
        "decompilerInferred" : {
            "composite" : [ ],
            "array" : [ ],
            "primitive" : [ ]
        },
        "decompiledCode" : {
            "0x12ec88" : "\nvoid fastcgi_get_packet_body(undefined8 param_1,long param_2,ForgedStruct_123 *param_3)\n\n{\n  undefined8 uVar1;\n  int iVar2;\n  int iVar3;\n  undefined8 uVar4;\n  \n  iVar2 = buffer_clen(param_1);\n  uVar1 = *(undefined8 *)(*(long *)(param_2 + 0x100) + 0x60);\n  iVar3 = param_3->field_0x0;\n  uVar4 = buffer_string_prepare_append(param_1,param_3->field_0x0);\n  iVar3 = chunkqueue_read_data(*(undefined8 *)(param_2 + 0x28),uVar4,iVar3,uVar1);\n  if (-1 < iVar3) {\n    buffer_truncate(param_1,(param_3->field_0x0 + iVar2) - param_3->field_0x8);\n  }\n  return;\n}\n\n",
            "0x12ead4" : "\nundefined8 fastcgi_get_packet(long param_1,ForgedStruct_123 *param_2)\n\n{\n  int iVar1;\n  undefined8 uVar2;\n  long in_FS_OFFSET;\n  int local_2c;\n  undefined8 *local_28;\n  ulong local_20;\n  undefined8 local_18;\n  long local_10;\n  \n  local_10 = *(long *)(in_FS_OFFSET + 0x28);\n  local_20 = chunkqueue_length(*(undefined8 *)(param_1 + 0x28));\n  if ((long)local_20 < 8) {\n    if ((*(int *)(param_1 + 0xf8) != 0) && (local_20 != 0)) {\n      log_debug(*(undefined8 *)(*(long *)(param_1 + 0x100) + 0x60),\"mod_fastcgi.c\",0x136,\n                \"FastCGI: header too small: %lld bytes < %zu bytes, waiting for more data\",local_20,\n                8);\n    }\n    uVar2 = 0xffffffff;\n  }\n  else {\n    local_28 = &local_18;\n    local_2c = 8;\n    iVar1 = chunkqueue_peek_data\n                      (*(undefined8 *)(param_1 + 0x28),&local_28,&local_2c,\n                       *(undefined8 *)(*(long *)(param_1 + 0x100) + 0x60),0);\n    if (iVar1 < 0) {\n      uVar2 = 0xffffffff;\n    }\n    else if (local_2c == 8) {\n      if (local_28 != &local_18) {\n        local_18 = *local_28;\n      }\n      param_2->field_0x0 = (uint)local_18._6_1_ + (uint)CONCAT11(local_18._4_1_,local_18._5_1_);\n      param_2->field_0xc = (uint)CONCAT11(local_18._2_1_,local_18._3_1_);\n      param_2->field_0x4 = (uint)local_18._1_1_;\n      param_2->field_0x8 = (uint)local_18._6_1_;\n      if ((local_20 & 0xffffffff) - 8 < (ulong)(uint)param_2->field_0x0) {\n        uVar2 = 0xffffffff;\n      }\n      else {\n        chunkqueue_mark_written(*(undefined8 *)(param_1 + 0x28),8);\n        uVar2 = 0;\n      }\n    }\n    else {\n      uVar2 = 0xffffffff;\n    }\n  }\n  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {\n                    /* WARNING: Subroutine does not return */\n    __stack_chk_fail();\n  }\n  return uVar2;\n}\n\n"
        }
        },
        "int" : {
        "desc" : "Primitive",
        "type" : "int",
        "decompiledCode" : {
            "0x12ec88" : "\nvoid fastcgi_get_packet_body(undefined8 param_1,long param_2,int *param_3)\n\n{\n  undefined8 uVar1;\n  int iVar2;\n  int iVar3;\n  undefined8 uVar4;\n  \n  iVar2 = buffer_clen(param_1);\n  uVar1 = *(undefined8 *)(*(long *)(param_2 + 0x100) + 0x60);\n  iVar3 = *param_3;\n  uVar4 = buffer_string_prepare_append(param_1,*param_3);\n  iVar3 = chunkqueue_read_data(*(undefined8 *)(param_2 + 0x28),uVar4,iVar3,uVar1);\n  if (-1 < iVar3) {\n    buffer_truncate(param_1,(*param_3 + iVar2) - param_3[2]);\n  }\n  return;\n}\n\n",
            "0x12ead4" : "\nundefined8 fastcgi_get_packet(long param_1,int *param_2)\n\n{\n  int iVar1;\n  undefined8 uVar2;\n  long in_FS_OFFSET;\n  int local_2c;\n  undefined8 *local_28;\n  ulong local_20;\n  undefined8 local_18;\n  long local_10;\n  \n  local_10 = *(long *)(in_FS_OFFSET + 0x28);\n  local_20 = chunkqueue_length(*(undefined8 *)(param_1 + 0x28));\n  if ((long)local_20 < 8) {\n    if ((*(int *)(param_1 + 0xf8) != 0) && (local_20 != 0)) {\n      log_debug(*(undefined8 *)(*(long *)(param_1 + 0x100) + 0x60),\"mod_fastcgi.c\",0x136,\n                \"FastCGI: header too small: %lld bytes < %zu bytes, waiting for more data\",local_20,\n                8);\n    }\n    uVar2 = 0xffffffff;\n  }\n  else {\n    local_28 = &local_18;\n    local_2c = 8;\n    iVar1 = chunkqueue_peek_data\n                      (*(undefined8 *)(param_1 + 0x28),&local_28,&local_2c,\n                       *(undefined8 *)(*(long *)(param_1 + 0x100) + 0x60),0);\n    if (iVar1 < 0) {\n      uVar2 = 0xffffffff;\n    }\n    else if (local_2c == 8) {\n      if (local_28 != &local_18) {\n        local_18 = *local_28;\n      }\n      *param_2 = (uint)local_18._6_1_ + (uint)CONCAT11(local_18._4_1_,local_18._5_1_);\n      param_2[3] = (uint)CONCAT11(local_18._2_1_,local_18._3_1_);\n      param_2[1] = (uint)local_18._1_1_;\n      param_2[2] = (uint)local_18._6_1_;\n      if ((local_20 & 0xffffffff) - 8 < (ulong)(uint)*param_2) {\n        uVar2 = 0xffffffff;\n      }\n      else {\n        chunkqueue_mark_written(*(undefined8 *)(param_1 + 0x28),8);\n        uVar2 = 0;\n      }\n    }\n    else {\n      uVar2 = 0xffffffff;\n    }\n  }\n  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {\n                    /* WARNING: Subroutine does not return */\n    __stack_chk_fail();\n  }\n  return uVar2;\n}\n\n"
        }
        }
    }
    """
    type_data = constraint["globalMorph"]
    all_player = []
    for type_name, data in type_data.items():
        player = Player(type_name, data["decompiledCode"])
        all_player.append(player)

    return constraint

######################################### Following is for testing purposes #########################################
def make_players(n):
    return [Player(f"player{i}") for i in range(n)]


if __name__ == "__main__":
    players = make_players(2)
    tournament = DoubleEliminationTournament(players)
    tournament.create_initial_matches()
    
    while True:
        print(f"====================== Current Round ======================")
        ready_matches = tournament.get_ready_matches()
        if not ready_matches:
            break
        
        print(f"Ready Matches: {ready_matches}")
        print(f"Judging .....................")
        for match in ready_matches:
            match.judge()
            winner = match.get_winner()
            loser = match.get_loser()
            print(f"Match Result: {match} - Winner: {winner.name}, Loser: {loser.name}")
        
        print(f"---------------------- Updated Result ----------------------")
        tournament.process_results()
        winners_bracket = tournament.get_winners_bracket()
        losers_bracket = tournament.get_losers_bracket()

        print(f"Next Round Winners Bracket: {winners_bracket}")
        print()
        print(f"Next Round Losers Bracket: {losers_bracket}")
        print(f"======================= Current Round end =======================")
        
    
    print(f"Champion: {tournament.get_champion().name}")
    print(f"Eliminated Players: {[player.name for player in tournament.eliminated]}")