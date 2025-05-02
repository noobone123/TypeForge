from typing import Dict, List, Tuple

class Player:
    def __init__(self, type_name: str, decompiled_code: dict):
        self.type_name = type_name
        self.decompiled_code = decompiled_code

    def __hash__(self):
        return hash(self.type_name)

    def __eq__(self, other):
        return isinstance(other, Player) and self.type_name == other.type_name

    def __repr__(self):
        return f"Player({self.type_name})"

class DoubleEliminationTournament:

    class Pair:
        def __init__(self, player1: Player, player2: Player):
            self.player1 = player1
            self.player2 = player2
            self.winner = None

        def judge(self) -> Player:
            # Randomly select a winner instead of always picking player1
            import random
            self.winner = random.choice([self.player1, self.player2])
            return self.winner
        
        def get_winner(self) -> Player:
            return self.winner

    def __init__(self, players: List[Player]):
        self.players = players
        # 初始时所有选手都在胜者组
        self.winners_bracket = players.copy()
        self.losers_bracket = []
        # 已经被淘汰的选手
        self.eliminated = []
        # 记录选手的失败次数
        self.losses = {player: 0 for player in players}
        # 本轮比赛的配对
        self.current_pairs = []
        # 当前是否在胜者组进行比赛
        self.is_winners_bracket = True
        # 是否已经产生了最终胜者
        self.is_finished = False
        # 最终胜者
        self.champion = None
        # 记录轮次
        self.round = 0

    def get_next_round(self) -> List[Pair]:
        """
        Double elimination tournament contains many rounds.
        Each round contains pairs of players, and these pairs can be evaluated in parallel.
        This function returns the pairs of players for the next round.
        If there is an odd number of players, one player will get a bye.
        If the tournament is over and the final winner is determined, return an empty list.
        """
        if self.is_finished:
            return []

        self.round += 1
        self.current_pairs = []

        # 处理胜者组
        if self.is_winners_bracket and len(self.winners_bracket) > 1:
            pairs = []
            bye_player = None
            if len(self.winners_bracket) % 2 != 0:
                bye_player = self.winners_bracket.pop()  # 轮空选手本轮不参与配对
            for i in range(0, len(self.winners_bracket), 2):
                if i + 1 < len(self.winners_bracket):
                    pair = self.Pair(self.winners_bracket[i], self.winners_bracket[i + 1])
                    pairs.append(pair)
            self.current_pairs = pairs
            self.is_winners_bracket = False
            # 赛后将轮空选手加入下一轮
            if bye_player is not None:
                self.winners_bracket = [p for p in self.winners_bracket if p not in [pair.player1 for pair in pairs] and p not in [pair.player2 for pair in pairs]]
                self.winners_bracket.append(bye_player)
            return pairs

        # 处理败者组
        elif not self.is_winners_bracket and len(self.losers_bracket) > 1:
            pairs = []
            bye_player = None
            if len(self.losers_bracket) % 2 != 0:
                bye_player = self.losers_bracket.pop()
            for i in range(0, len(self.losers_bracket), 2):
                if i + 1 < len(self.losers_bracket):
                    pair = self.Pair(self.losers_bracket[i], self.losers_bracket[i + 1])
                    pairs.append(pair)
            self.current_pairs = pairs
            self.is_winners_bracket = True
            if bye_player is not None:
                self.losers_bracket = [p for p in self.losers_bracket if p not in [pair.player1 for pair in pairs] and p not in [pair.player2 for pair in pairs]]
                self.losers_bracket.append(bye_player)
            return pairs
            
        # 新增：败者组只剩一人时，切回胜者组等待决赛
        elif not self.is_winners_bracket and len(self.losers_bracket) == 1:
            self.is_winners_bracket = True
            return self.get_next_round()  # 立即触发下一轮
            
        # 处理决赛（胜者组最后一人 vs 败者组最后一人）
        elif len(self.winners_bracket) == 1 and len(self.losers_bracket) == 1:
            # 创建胜者组冠军与败者组冠军的对决
            final_pair = self.Pair(self.winners_bracket[0], self.losers_bracket[0])
            self.current_pairs = [final_pair]
            self.is_finished = True  # 比赛将在此轮结束
            return [final_pair]
        
        # 如果胜者组只剩一人且败者组为空，则该选手为冠军
        elif len(self.winners_bracket) == 1 and len(self.losers_bracket) == 0:
            self.champion = self.winners_bracket[0]
            self.is_finished = True
            return []
        
        # 如果只有败者组剩一人，则该选手为冠军
        elif len(self.winners_bracket) == 0 and len(self.losers_bracket) == 1:
            self.champion = self.losers_bracket[0]
            self.is_finished = True
            return []
            
        # 如果比赛已经结束但没有冠军，则选择剩余玩家中的一个作为冠军
        elif self.is_finished and self.champion is None:
            remaining_players = self.winners_bracket + self.losers_bracket
            if remaining_players:
                self.champion = remaining_players[0]
            return []
        
        # 其他情况（理论上不应该发生）
        else:
            # 如果因某种原因没有玩家了，但比赛未结束，则标记为已结束
            if len(self.winners_bracket) == 0 and len(self.losers_bracket) == 0 and not self.is_finished:
                self.is_finished = True
            return []
    
    def process_results(self):
        """
        处理当前轮次的比赛结果，更新选手状态
        """
        if not self.current_pairs:
            return
        
        # 临时存储获胜者，用于更新胜者组
        round_winners = []
        
        for pair in self.current_pairs:
            winner = pair.get_winner()
            if winner is None:
                continue
            
            # 记录这一轮的获胜者
            round_winners.append(winner)
                
            loser = pair.player2 if winner == pair.player1 else pair.player1
            
            # 更新失败计数
            self.losses[loser] = self.losses.get(loser, 0) + 1
            
            # 如果是第一次失败，进入败者组
            if self.losses[loser] == 1:
                if loser in self.winners_bracket:
                    self.winners_bracket.remove(loser)
                if loser not in self.losers_bracket:
                    self.losers_bracket.append(loser)
            # 如果是第二次失败，彻底淘汰
            elif self.losses[loser] >= 2:
                if loser in self.losers_bracket:
                    self.losers_bracket.remove(loser)
                if loser in self.winners_bracket:
                    self.winners_bracket.remove(loser)
                if loser not in self.eliminated:
                    self.eliminated.append(loser)
        
        # 处理胜者组的比赛结果
        if self.is_winners_bracket == False:  # 刚刚进行了胜者组比赛
            # 清除胜者组中参赛的选手（败者已在上面移除）
            participants = [p.player1 for p in self.current_pairs] + [p.player2 for p in self.current_pairs]
            self.winners_bracket = [p for p in self.winners_bracket if p not in participants]
            # 将获胜者添加回胜者组
            for winner in round_winners:
                if winner not in self.winners_bracket:
                    self.winners_bracket.append(winner)
        
        # 如果是最后一场比赛，确定冠军
        if self.is_finished and len(self.current_pairs) == 1:
            winner = self.current_pairs[0].get_winner()
            self.champion = winner
            
            # 确保最终冠军不在任何分组中
            if winner in self.winners_bracket:
                self.winners_bracket.remove(winner)
            if winner in self.losers_bracket:
                self.losers_bracket.remove(winner)
            
            # 最后一场比赛的败者直接进入淘汰名单
            loser = self.current_pairs[0].player1 if winner == self.current_pairs[0].player2 else self.current_pairs[0].player2
            if loser in self.winners_bracket:
                self.winners_bracket.remove(loser)
            if loser in self.losers_bracket:
                self.losers_bracket.remove(loser)
            if loser not in self.eliminated:
                self.eliminated.append(loser)
                
        # 清空当前比赛对
        self.current_pairs = []
    
    def get_champion(self) -> Player:
        """
        返回最终冠军，如果比赛尚未结束返回None
        """
        return self.champion if self.is_finished else None
    

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

