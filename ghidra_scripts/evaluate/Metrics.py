import json
import os
import pathlib
import argparse
from typing import Dict, List, Tuple, Union

class Metrics:
    def __init__(self, gt_dir, result_dir, binary_name):
        self.gt_dir = gt_dir
        self.result_dir = result_dir
        self.binary_name = binary_name

        self.gt_vartype = {}
        self.infer_vartype = {}

        # statistics for task1
        self.gt_total_composite_type_count = 0
        self.infer_total_composite_type_count = 0
        self.task1_correct_count = 0

        # statistics for task2
        self.gt_total_member_count = 0
        self.infer_total_member_count = 0
        self.task2_correct_count = 0

        # get all file paths starting with 'Skeleton_' in result_dir
        self.result_files = [f for f in os.listdir(result_dir) if f.startswith('Skeleton_')]
        self.skt_to_file: Dict = {}
        for file in self.result_files:
            skt = file.split('_')[:2]
            skt = '_'.join(skt)
            self.skt_to_file[skt] = file


    def load_ground_truth(self, gt_vartype_path):
        with open(gt_vartype_path, 'r') as f:
            self.gt_vartype = json.load(f)
        self.__post_handle_gt()
        print(f"Total composite type count in ground truth: {self.gt_total_composite_type_count}")


    def load_result(self, result_vartype_path):
        with open(result_vartype_path, 'r') as f:
            self.infer_vartype = json.load(f)
        self.__post_handle_infer()


    def __post_handle_gt(self):
        for func_ea in self.gt_vartype:
            params: Dict = self.gt_vartype[func_ea]['Parameters']
            localvars: Dict = self.gt_vartype[func_ea]['LocalVariables']
            for param in params.items():
                param_name = param[0]
                param_info: Dict = param[1]
                if self.__is_composite_type_gt(param_info):
                    self.gt_total_composite_type_count += 1

            for localvar in localvars.items():
                localvar_name = localvar[0]
                localvar_info: Dict = localvar[1]
                if self.__is_composite_type_gt(localvar_info):
                    self.gt_total_composite_type_count += 1


    def __post_handle_infer(self):
        for func_ea in self.infer_vartype:
            params: Dict = self.infer_vartype[func_ea]['Parameters']
            localVars: Dict = self.infer_vartype[func_ea]['LocalVariables']
            for param in params.items():
                param_name = param[0]
                param_info = param[1]
                if self.__is_composite_type_infer(param_info):
                    self.infer_total_composite_type_count += 1
                if self.__task1_correct(func_ea, True, param_name, param_info):
                    self.task1_correct_count += 1

            for localvar in localVars.items():
                localvar_name = localvar[0]
                localvar_info = localvar[1]
                if self.__is_composite_type_infer(localvar_info):
                    self.infer_total_composite_type_count += 1
                if self.__task1_correct(func_ea, False, localvar_name, localvar_info):
                    self.task1_correct_count += 1


        print(f"Task1 Recall: ", self.task1_correct_count / self.gt_total_composite_type_count)
        print(f"Task1 Precision: ", self.task1_correct_count / self.infer_total_composite_type_count)


    def __task1_correct(self, func_ea: str, is_param: bool, var_name: str, var_info: Dict) -> bool:
        func_ea_gt = self.__func_ea_to_gt(func_ea)
        gt_info = None
        if is_param:
            gt_params = self.gt_vartype[func_ea_gt]['Parameters']
            if var_name not in gt_params:
                return True

            gt_info = gt_params[var_name]
        else:
            var_storage = var_name
            gt_locals = self.gt_vartype[func_ea_gt]['LocalVariables']
            
            if var_storage not in gt_locals:
                return True
            gt_info = gt_locals[var_name]
        
        if self.__is_composite_type_gt(gt_info) and self.__is_composite_type_infer(var_info):
            return True
        else:
            return False


    def __is_composite_type_gt(self, var_info: Dict) -> bool:
        return 'Struct' in var_info['desc'] or 'Union' in var_info['desc']
    

    def __is_composite_type_infer(self, var_info: Dict) -> bool:
        var_skt = var_info['Skeleton']
        skt_file = self.skt_to_file[var_skt]
        if "final" in skt_file:
            return True
        if "range" in skt_file:
            return True
        if "global" in skt_file:
            return False
        
    def __func_ea_to_gt(self, func_ea: str) -> str:
        # 0x134c63 to 0x00134c63
        return '0x' + func_ea[2:].zfill(8)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Metrics')
    parser.add_argument('--result-dir', required=True, type=str, help='Directory containing the results')
    parser.add_argument('--ground-truth-dir', required=True, type=str, help='Directory containing the ground truth')
    parser.add_argument('--binary-name', required=True, type=str, help='Name of the target binary')
    args = parser.parse_args()


    gt_dir = args.ground_truth_dir
    result_dir = args.result_dir
    binary_name = args.binary_name

    gt_vartype_path = pathlib.Path(gt_dir) / f"{binary_name}_varType.json"
    gt_typeLib_path = pathlib.Path(gt_dir) / f"{binary_name}_typeLib.json"
    result_vartype_path = pathlib.Path(result_dir) / "varType.json"

    metrics = Metrics(gt_dir, result_dir, binary_name)
    metrics.load_ground_truth(gt_vartype_path)
    metrics.load_result(result_vartype_path)

