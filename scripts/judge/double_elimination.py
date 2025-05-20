from typing import List, Optional, Dict, Set, Tuple
import random
import asyncio
from llm import judge_readability

class Player:
    def __init__(self, name: str, decompiled_code: Optional[Dict[str, str]] = None):
        self.name = name
        self.bracket = "winners"  # can be "winners", "losers", "eliminated" or "champion"
        if decompiled_code:
            self.decompiled_code = decompiled_code

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

    def judge_test(self):
        # Randomly select a winner instead of always picking player1
        self.winner = random.choice([self.player1, self.player2])
        self.loser = self.player1 if self.winner == self.player2 else self.player2
    
    def judge(self):
        """
        Make Decompiled Code Pairs of Players, and run them using asyncio.
        """
        # TODO: If the number of code pairs is too large, we need to sample them.
        decompiled_code_pairs: List[Tuple[str, str]]
        assert self.player1.decompiled_code.keys() == self.player2.decompiled_code.keys(), "Decompiled code keys do not match"
        decompiled_code_pairs = [(self.player1.decompiled_code[key], self.player2.decompiled_code[key]) for key in self.player1.decompiled_code.keys()]
        
        results = asyncio.run(judge_readability(decompiled_code_pairs))
        
        # Post handle the results
        print(results)
        print(results.count(0), results.count(1))
        # results is a list of 0 or 1
        # 0 means player1 is better, 1 means player2 is better
        if results.count(0) > results.count(1):
            self.winner = self.player1
            self.loser = self.player2
        else:
            self.winner = self.player2
            self.loser = self.player1
            
    async def judge_async(self):
        """
        Asynchronous version of the judge method that doesn't use asyncio.run().
        """
        try:
            # TODO: If the number of code pairs is too large, we need to sample them.
            decompiled_code_pairs: List[Tuple[str, str]]
            assert self.player1.decompiled_code.keys() == self.player2.decompiled_code.keys(), "Decompiled code keys do not match"
            decompiled_code_pairs = [(self.player1.decompiled_code[key], self.player2.decompiled_code[key]) for key in self.player1.decompiled_code.keys()]
            
            # Direct async call without asyncio.run()
            results = await judge_readability(decompiled_code_pairs)
                        
            if not results:  # If results is empty or None
                print("No results returned, defaulting to player1 as winner")
                self.winner = self.player1
                self.loser = self.player2
                return
            
            # print(results)
            # print(results.count(0), results.count(1))
            # results is a list of 0 or 1
            # 0 means player1 is better, 1 means player2 is better
            if results.count(0) > results.count(1):
                self.winner = self.player1
                self.loser = self.player2
            else:
                self.winner = self.player2
                self.loser = self.player1
        except Exception as e:
            print(f"Error in judge_async: {str(e)}")
            # Default to player1 as winner in case of exception
            self.winner = self.player1
            self.loser = self.player2

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

async def run_async(constraint: Dict, morph_file_name: str) -> Dict:
    """
    Asynchronous version of the run function.
    
    Args:
        constraint: Dictionary containing the type constraints
        
    Returns:
        The processed constraint dictionary
    """
    if "desc" in constraint and constraint["desc"] == "NoRetypeCandidates":
        return None
    
    all_player = []
    if "globalMorph" in constraint:
        type_data = constraint["globalMorph"]
        for type_name, data in type_data.items():
            player = Player(type_name, data["decompiledCode"])
            all_player.append(player)

    # TODO: handle rangeMorph multi and rangeMorph single here.

    tournament = DoubleEliminationTournament(all_player)
    tournament.create_initial_matches()
    
    while True:
        ready_matches = tournament.get_ready_matches()
        if not ready_matches:
            break
        
        # Process matches concurrently using judge_async
        match_tasks = []
        for match in ready_matches:
            # Use the async version directly - no need for to_thread
            match_tasks.append(match.judge_async())
        
        # Wait for all matches to complete
        await asyncio.gather(*match_tasks)
        tournament.process_results()        
    
    print(f"Champion of {morph_file_name}: {tournament.get_champion().name}")
    print(f"\tAll players: {[player.name for player in tournament.players]}")
    # Update the final champion in the constraint
    return constraint

# Keep the synchronous version for backward compatibility
def run(constraint: Dict) -> Dict:
    """
    Synchronous version of the run function.
    This is kept for backward compatibility.
    """
    if "desc" in constraint and constraint["desc"] == "NoRetypeCandidates":
        return None
    
    all_player = []
    if "globalMorph" in constraint:
        type_data = constraint["globalMorph"]
        for type_name, data in type_data.items():
            player = Player(type_name, data["decompiledCode"])
            all_player.append(player)

    # TODO: handle rangeMorph multi and rangeMorph single here.

    tournament = DoubleEliminationTournament(all_player)
    tournament.create_initial_matches()
    
    while True:
        ready_matches = tournament.get_ready_matches()
        if not ready_matches:
            break
        
        for match in ready_matches:
            match.judge()

        tournament.process_results()        
    
    print(f"Champion: {tournament.get_champion().name}")
    return constraint

######################################### Following is for testing purposes #########################################
def make_players(n):
    return [Player(f"player{i}") for i in range(n)]

def print_bracket(bracket):
    # sort the bracket by level
    sorted_bracket = sorted(bracket.items(), key=lambda x: x[0])
    for level, players in sorted_bracket:
        print(f"Level {level}:")
        print(players)

if __name__ == "__main__":
    # Test the Double Elimination Tournament
    players = make_players(8)
    tournament = DoubleEliminationTournament(players)
    tournament.create_initial_matches()
    
    while True:
        print(f"====================== Current Round ======================")
        print(f" ** Winner Bracket: ** ")
        print_bracket(tournament.winners_bracket)
        print(f" !! Loser Bracket: !!")
        print_bracket(tournament.losers_bracket)
        print(f"Eliminated Players:")
        print(tournament.eliminated)

        ready_matches = tournament.get_ready_matches()
        if not ready_matches:
            break
        
        print(f"Ready Matches: {ready_matches}")
        print(f"Judging .....................")
        for match in ready_matches:
            match.judge_test()
            winner = match.get_winner()
            loser = match.get_loser()
            print(f"Match Result: {match} - Winner: {winner.name}, Loser: {loser.name}")
        
        tournament.process_results()
        print(f"======================= Current Round end =======================")
        
    
    print(f"Champion: {tournament.get_champion().name}")
    print(f"Eliminated Players: {[player.name for player in tournament.eliminated]}")
    
    # To test run_async, uncomment the following code:
    # import asyncio
    # 
    # async def test_run_async():
    #     # Create a test constraint
    #     test_constraint = {
    #         "globalMorph": {
    #             "type1": {"decompiledCode": {"file1": "code1", "file2": "code2"}},
    #             "type2": {"decompiledCode": {"file1": "code3", "file2": "code4"}}
    #         }
    #     }
    #     result = await run_async(test_constraint)
    #     print("Run async test completed with result:", result)
    # 
    # # Run the test
    # asyncio.run(test_run_async())