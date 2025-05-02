import pytest
from double_elimination import Player, DoubleEliminationTournament

def make_players(n):
    return [Player(f"player{i}", {}) for i in range(n)]

def test_even_players():
    players = make_players(4)
    t = DoubleEliminationTournament(players)
    round1 = t.get_next_round()
    print(f"Round 1 pairs: {[ (p.player1, p.player2) for p in round1 ]}")
    assert len(round1) == 2
    for pair in round1:
        pair.judge()
    t.process_results()
    round2 = t.get_next_round()
    print(f"Round 2 pairs: {[ (p.player1, p.player2) for p in round2 ]}")
    assert len(round2) == 1 or len(round2) == 2  # 败者组也可能有比赛

def test_odd_players_bye():
    players = make_players(5)
    t = DoubleEliminationTournament(players)
    round1 = t.get_next_round()
    print(f"Round 1 pairs: {[ (p.player1, p.player2) for p in round1 ]}")
    assert len(round1) == 2  # 5人，1人轮空，2组配对
    for pair in round1:
        pair.judge()
    t.process_results()
    # 轮空选手应自动进入下一轮
    print(f"Winners after round 1: {t.winners_bracket}")
    assert len(t.winners_bracket) == 3

def test_elimination():
    players = make_players(3)
    t = DoubleEliminationTournament(players)
    # 第一轮
    round1 = t.get_next_round()
    print(f"Round 1 pairs: {[ (p.player1, p.player2) for p in round1 ]}")
    for pair in round1:
        pair.judge()
    t.process_results()
    # 第二轮
    round2 = t.get_next_round()
    print(f"Round 2 pairs: {[ (p.player1, p.player2) for p in round2 ]}")
    for pair in round2:
        pair.judge()
    t.process_results()
    # 第三轮（让败者组有人输第二次）
    round3 = t.get_next_round()
    print(f"Round 3 pairs: {[ (p.player1, p.player2) for p in round3 ]}")
    for pair in round3:
        pair.judge()
    t.process_results()
    print(f"Eliminated: {t.eliminated}")
    # 检查淘汰人数
    assert len(t.eliminated) >= 1

def test_final_match():
    players = make_players(2)
    t = DoubleEliminationTournament(players)
    round1 = t.get_next_round()
    print(f"Round 1 pairs: {[ (p.player1, p.player2) for p in round1 ]}")
    for pair in round1:
        pair.judge()
    t.process_results()
    round2 = t.get_next_round()
    print(f"Round 2 pairs: {[ (p.player1, p.player2) for p in round2 ]}")
    for pair in round2:
        pair.judge()
    t.process_results()
    # 决赛后应有冠军
    print(f"Champion: {t.get_champion()}")
    assert t.get_champion() is not None

def test_champion_with_bye():
    players = make_players(1)
    t = DoubleEliminationTournament(players)
    round1 = t.get_next_round()
    print(f"Round 1 pairs: {round1}")
    assert round1 == []
    assert t.get_champion() == players[0]

if __name__ == "__main__":
    pytest.main([__file__])