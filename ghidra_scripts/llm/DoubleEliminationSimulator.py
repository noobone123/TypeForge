import re
import random
from typing import List, Dict
import os
import time 
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import ast
import multiprocessing
import time
import signal
import argparse
import json
import yaml
import pathlib

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Task timed out")


def generate_random_c_function():
    """Generate a more complex random C function."""
    def random_identifier():
        """Generate a random C variable or function name."""
        return 'var_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))

    def random_type():
        """Generate a random C type."""
        return random.choice(['int', 'float', 'double', 'char'])

    def random_value(c_type):
        """Generate a random value based on the C type."""
        if c_type == 'int':
            return str(random.randint(0, 100))
        elif c_type in ['float', 'double']:
            return f"{random.uniform(0, 100):.2f}"
        elif c_type == 'char':
            return "'" + random.choice('abcdefghijklmnopqrstuvwxyz') + "'"
        return '0'

    # Generate random function components
    return_type = random_type()
    function_name = random_identifier()
    param_type = random_type()
    param_name = random_identifier()

    # Generate a more complex function body
    body = f"    {return_type} result = {random_value(return_type)};\n"
    body += f"    {return_type} {random_identifier()} = {random_value(return_type)};\n"
    
    # Add a simple loop
    body += f"    for(int i = 0; i < 5; i++) {{\n"
    if return_type in ['int', 'float', 'double']:
        body += f"        result += {random.choice(['1', '0.5', 'i'])};\n"
    body += "    }\n"

    # Add a simple conditional statement
    if return_type in ['int', 'float', 'double']:
        body += f"    if (result > 50) {{\n"
        body += f"        result -= 10;\n"
        body += "    } else {\n"
        body += f"        result += 10;\n"
        body += "    }\n"

    # Add a print statement if applicable
    if return_type == 'int':
        body += "    printf(\"Result is: %d\\n\", result);\n"
    elif return_type in ['float', 'double']:
        body += "    printf(\"Result is: %.2f\\n\", result);\n"
    elif return_type == 'char':
        body += "    printf(\"Result is: %c\\n\", result);\n"

    body += "    return result;\n"

    # Construct the function
    function = f"{return_type} {function_name}({param_type} {param_name}) {{\n"
    function += body
    function += "}\n"
    return function

class Player:
    def __init__(self, name: str , deccodes):
        self.name = name
        self.deccodes = deccodes


    def __repr__(self):
        return f"Player_{self.name}"

def play_match(player1: Player, player2: Player) -> Player:
    results = {}
    questions = []
    length = len(player1.deccodes)
    last_start_index = ( (length-1)// 5) * 5
    last_length =  length - last_start_index
    # print(length)
    # print(last_start_index)
    # print(last_length)
    matches = []
    for i in range(length):
        matches.append((player1.deccodes[i],player2.deccodes[i]))
    for i in range(0,len(matches),5):
        if i == last_start_index:  
            snippets = [] 
            for j in range(last_length):    
                snippets.append(matches[i+j][0]) 
                snippets.append(matches[i+j][1]) 
            for k in range(5-last_length):
                snippets.append('padding')
                snippets.append('padding')
            #print(snippets)
            
            tmp_dict = {}
            for f in range(10):
                tmp_dict["snippet"+ str(f+1)] = snippets[f]
            questions.append(tmp_dict)
 
        else:
            questions.append({"snippet1":matches[i][0],"snippet2":matches[i][1],"snippet3":matches[i+1][0],"snippet4":matches[i+1][1],"snippet5":matches[i+2][0],"snippet6":matches[i+2][1],"snippet7":matches[i+3][0],"snippet8":matches[i+3][1],"snippet9":matches[i+4][0],"snippet10":matches[i+4][1]})               

    #根据需要更改frequency
    res_gpt4omini = chain_gpt4omini.batch(questions, config={"max_concurrency": args.langfreq})
    answers =  []
    for i in range(len(questions)):
        try:
            actual_list = ast.literal_eval(res_gpt4omini[i].content)
        except:
            print('fail to parse llm ouput, just extract first 5 0/1/2')
            digits = re.findall(r'[012]', res_gpt4omini[i].content)
            actual_list = matches[:5]

        answers.extend(actual_list)

    sum0 = 0
    sum1 = 0

    for i in range(length):
        if '0'  ==  answers[i]:
            sum0 +=1
        elif '1' == answers[i]:
            sum1 +=1
        else:
            sum0 +=1
            sum1 +=1
    return player1 if sum0>sum1 else player2

def double_elimination_(players: List[Player]) -> Player:
    winners = players[:]
    losers = []
    
    
    round_number = 1
    while len(winners) > 1 or len(losers) > 1:
        # print(f"Round {round_number}")
        # print(f"Winners Bracket: {len(winners)} players, and they are {winners}")
        # print(f"Losers Bracket: {len(losers)} players, and they are {losers}")

        # shuffle
        random.shuffle(winners)
        random.shuffle(losers)

        new_winners = []
        new_losers = []

        # Winners bracket matches
        for i in range(0, len(winners) - 1, 2):
            player1 = winners[i]
            player2 = winners[i + 1]
            loser = play_match(player1, player2)
            winner = player1 if loser == player2 else player2
            # print(f"Match: {player1} vs {player2}, Loser: {loser}")

            new_winners.append(winner)
            new_losers.append(loser)

        # If odd number of players, last one gets a bye
        if len(winners) % 2 == 1:
            new_winners.append(winners[-1])

        # print(f"Round {round_number} - Losers Bracket")
        next_round_losers = []

        # Losers bracket matches
        if len(losers) > 1:
            for i in range(0, len(losers) - 1, 2):
                player1 = losers[i]
                player2 = losers[i + 1]
                loser = play_match(player1, player2)
                winner = player1 if loser == player2 else player2
                # print(f"Match: {player1} vs {player2}, Loser: {loser}")

                next_round_losers.append(winner)

            # If odd number of players, last one gets a bye
            if len(losers) % 2 == 1:
                next_round_losers.append(losers[-1])

        # Update the lists for the next round
        winners = new_winners
        losers = next_round_losers + new_losers
        round_number += 1

    if len(winners) == 1 and len(losers) == 1:
        # print("Final match")
        final_winner = play_match(winners[0], losers[0])
        # print(f"Final Match: {winners[0]} vs {losers[0]}, Winner: {final_winner}")
        return final_winner
    return winners[0] if winners else losers[0]


def double_elimination(typename_dict:dict)-> str:
    start_time = time.time()
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(args.pertime)  
    
    try:
        offsets = []
        for k,v in typename_dict.items():
            for k1,v1 in v.items():
                offsets.append(k1)
            break
        players = []
        for k,v in typename_dict.items():
            tmp_list = []
            for offset in offsets:
                tmp_list.append(v[offset])
            players.append(Player(k,tmp_list))

        winner = double_elimination_(players)
        result = winner.name
        status = "Success"
    except TimeoutException as te:
        result = None
        status = f"Failed: {str(te)}"
    except Exception as e:
        result = None
        status = f"Failed: {str(e)}"
    finally:
        signal.alarm(0)
    end_time = time.time()
    elapsed_time = end_time - start_time
    return (result, status, elapsed_time)


def read_config():
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    return config


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "double-elimination for best-fit")
    parser.add_argument('--langfreq', type = int, default = 64, help = 'max_concurrency of a batch langchain request')
    parser.add_argument('--procnum', type = int, default = 32, help = 'the num of proccess')
    parser.add_argument('--pertime', type = int, default = 60, help = 'the max excution time of one process')
    parser.add_argument('--respath', type = str, help = 'the directory of the inferred result', required = True)
    parser.add_argument('--verbose', type = str, choices = ['true', 'false'], default = 'false', help = 'print output')
    args = parser.parse_args()
    config = read_config()

    start_time = time.time()

    model = ChatOpenAI(model = config['llm']['model'], api_key = config['llm']['apikey'], base_url = config['llm']['url'])
    prompt = ChatPromptTemplate(
        [
            ("system", config["prompt"]["system"]),
            ("human",
            '''
            Assess which snippet has better readability in terms of syntax and semantics. For every snippet pair,
            if the first snippet is more readable, please indicate this with 0; if the second is more readable, please indicate this with 1, if both snippets are identical except for variable and type names, please indicate this with 2.
            Pair snippets : [<{snippet1} & {snippet2}> , <{snippet3} & {snippet4}> , <{snippet5} & {snippet6}> , <{snippet7} & {snippet8}> , <{snippet9} & {snippet10}>]
            You must only return a list as ['0/1/2','0/1/2','0/1/2', '0/1/2','0/1/2'] 
            ''')
        ]
    )
    chain_gpt4omini = prompt | model

    res_dir = args.respath
    res_list = []
    candidates = []
    filenames = os.listdir(res_dir)
    empty_global_num = 0
    empty_range_num = 0

    for filename in filenames:
        if 'final' in filename:
            continue
        
        filepath = pathlib.Path(res_dir + '/' + filename)
        with open(filepath, 'r', encoding = 'utf-8') as f:
            inferred_json = json.load(f)
        
        if 'global' in filename:
            if ('desc' in inferred_json and inferred_json['desc'] == "NoRetypeCandidates"):
                continue

            type_to_codes = {}
            for type_name, type_info in inferred_json['globalMorph'].items():
                if (type_info["decompiledCode"] == {}):
                    empty_global_num += 1
                    break
                type_to_codes[type_name] = type_info["decompiledCode"]

            candidates.append(type_to_codes)
            tmp_skeletion_dict = {}
            tmp_skeletion_desc_dict = {}
            tmp_skeletion_desc_dict['desc'] = 'global'
            split_list = filename.split('_')
            tmp_skeletion_dict[split_list[0]+ '_' + split_list[1]] = tmp_skeletion_desc_dict
            res_list.append(tmp_skeletion_dict)

        elif 'range' in filename:
            for interval in inferred_json['rangeMorph']:
                if ('desc' in interval and interval['desc'] == "NoRetypeCandidates"):
                    continue

                type_to_codes = {}
                for type_name, type_info in interval['types'].items():
                    if (type_info["decompiledCode"] == {}):
                        empty_range_num += 1
                        break
                    type_to_codes[type_name] = type_info["decompiledCode"]
                
                candidates.append(type_to_codes) 
                tmp_skeletion_dict = {}
                tmp_skeletion_desc_dict = {}
                tmp_skeletion_desc_dict['desc'] = 'range'
                tmp_skeletion_desc_dict['offset'] = interval['startOffset'] + '&' + interval['endOffset']
                split_list = filename.split('_')
                tmp_skeletion_dict[split_list[0]+ '_' + split_list[1]] = tmp_skeletion_desc_dict
                res_list.append(tmp_skeletion_dict)


    print(f"Empty global number: {empty_global_num}")
    print(f"Empty range number: {empty_range_num}")     
    print('===================')
    print(f"candidate count: {len(candidates)}")
    print(f"result list count: {len(res_list)}")

    # Main: Start the double elimination
    with multiprocessing.Pool(processes = args.procnum) as pool:
        results = pool.map(double_elimination, candidates)

    if args.verbose == 'true':
        print('===================')
        print('Result:')
        print(results)
        
    final_res = []
    assert len(res_list) == len(results)

    for i in range(len(res_list)):
        res_tmp_dict = {}
        res_tmp_dict_result = {}
        for k,v in res_list[i].items():
            if v['desc'] == 'global':                
                res_tmp_dict_result['desc'] = v['desc']
                res_tmp_dict_result['result'] = results[i][0]
                res_tmp_dict[k] = res_tmp_dict_result
                final_res.append(res_tmp_dict)
            elif v['desc'] == 'range':
                res_tmp_dict_result['desc'] = v['desc']
                tmp_tmp_dict = {}
                tmp_tmp_dict['startOffset'] = v['offset'].split('&')[0]
                tmp_tmp_dict['endOffset'] = v['offset'].split('&')[1]
                tmp_tmp_dict['result'] = results[i][0]
                res_tmp_dict_result['result'] = tmp_tmp_dict
                res_tmp_dict[k] = res_tmp_dict_result
                final_res.append(res_tmp_dict)

    if args.verbose == 'true':
        print('===================')
        print("final json:")
        print(final_res)
    end_time = time.time()
    elapsed_time = end_time - start_time
    print('===================')
    print(f"the time of best-fit this binary is {elapsed_time}s")
    with open('output.json', 'w') as file:
        json.dump(final_res, file, indent=4)
