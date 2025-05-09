import os
import json
from IPython import embed

class MetricAndResultLogger():
    def __init__(self, bin_name, func_name, dec_name):
        self.bin_name = bin_name
        self.cat_name = None
        self.p_name = None
        self.o_name = None
        self.comp_name = None
        self.opt_level = None

        self.func_name = func_name
        self.dec_name = dec_name

        self.total_analysis_time = 0
        self.angr_prep_time = 0
        self.dec_time = 0
        self.symbex_time = 0

        self.diverged_var = None
        self.diverged_step = None
        self.o_div_state_addr = None
        self.o_min = None
        self.o_max = None
        self.o_other_vals = None
        self.r_div_state_addr = None
        self.r_min = None
        self.r_max = None
        self.r_other_vals = None

        self.sloc = 0
        self.total_vars = 0
        self.non_pointer_vars = 0
        self.pointer_vars = 0
        self.rematch_total = 0
        self.rematch_successful = 0
        self.early_ret_total = 0
        self.early_ret_successful = 0
        self.o_total_func_calls = 0
        self.r_total_func_calls = 0 
        self.o_unique_func_calls = set()
        self.r_unique_func_calls = set()
        self.total_stepping = 0
        self.total_state_comparison = 0
        self.real_state_comparison = 0
        self.total_var_comparison = 0

        self.o_bblocks = None
        self.o_active = None
        self.o_returned = None
        self.o_queue = None
        self.o_errored = None
        self.o_unconstrained = None
        self.r_bblocks = None
        self.r_active = None
        self.r_returned = None
        self.r_queue = None
        self.r_errored = None
        self.r_unconstrained = None

        self.status = None
        self.result = None
        self.mem_usage = 0

        self.IO_res = None
        self.orig_ret_nums = None
        self.orig_ret_unique_nums = None
        self.unique_orig_vals = None
        self.orig_diffs = None
        self.recomp_ret_nums = None
        self.recomp_ret_unique_nums = None
        self.unique_recomp_vals = None
        self.recomp_diffs = None
    
    def get_log_dict(self):
        return self.log_dict
    
    def dump_json(self):

        with open(os.path.join("out/json_log", self.bin_name + "+" + self.func_name + "+"
                                                + self.dec_name + ".json"), "w") as f:
            json.dump(self.log_dict, f)

    def load_json(self):
        with open(os.path.join("out/json_log", self.bin_name + ".json"), "r") as f:
            t_d = json.load(f)

    def get_stashes(self, o_stashes, r_stashes):

        self.o_active = [hex(s.addr) for s in o_stashes['active']]
        self.o_returned = [hex(s.addr) for s in o_stashes['returned']]
        self.o_queue = [hex(s.addr) for s in o_stashes['queue']]
        self.o_errored = [hex(s.addr) for s in o_stashes['errored']]
        self.o_unconstrained = [hex(s.history.addr) for s in o_stashes['unconstrained']]

        self.r_active = [hex(s.addr) for s in r_stashes['active']]
        self.r_returned = [hex(s.addr) for s in r_stashes['returned']]
        self.r_queue = [hex(s.addr) for s in r_stashes['queue']]
        self.r_errored = [hex(s.addr) for s in r_stashes['errored']]
        self.r_unconstrained = [hex(s.history.addr) for s in r_stashes['unconstrained']]

    def fill_metric_dicts(self):
        self.cat_name, self.p_name, self.o_name, self.comp_name, self.opt_level, garbage = self.bin_name.split("#")
        
        self.angr_prep_time = round(self.angr_prep_time, 2)
        self.dec_time = round(self.dec_time, 2)
        self.symbex_time = round(self.symbex_time, 2)
        self.total_analysis_time = self.angr_prep_time + self.dec_time + self.symbex_time
        self.total_analysis_time = round(self.total_analysis_time, 2)
        self.mem_usage = round(self.mem_usage)


        self.analysis_time = {'total_analysis_time':self.total_analysis_time, 'angr_prep_time': self.angr_prep_time,
                             'dec_time':self.dec_time, 'symbex_time':self.symbex_time}

        self.divergence_info = {'diverged_var':self.diverged_var, 'diverged_step':self.diverged_step,
                        'diverged_orig':{'div_state_addr':self.o_div_state_addr, 'min':self.o_min,
                        'max':self.o_max, 'other_vals':self.o_other_vals},
                        'diverged_recomp':{'div_state_addr':self.r_div_state_addr, 'min':self.r_min,
                        'max':self.r_max, 'other_vals':self.r_other_vals}}

        self.analysis_info = {'dec_info':{'sloc':self.sloc, 'vars':{'total_vars':self.total_vars, 
                            'non_pointer_vars':self.non_pointer_vars, 'pointer_vars':self.pointer_vars}},
                            'rematch_attempts':{'total':self.rematch_total, 'successful':self.rematch_successful}, 
                            'early_ret_attempts':{'total': self.early_ret_total, 'successful':self.early_ret_successful},
                            'func_calls':{'o_total_func_calls':self.o_total_func_calls, 
                            'r_total_func_calls':self.r_total_func_calls, 'o_unique_func_calls':len(self.o_unique_func_calls),
                            'r_unique_func_calls':len(self.r_unique_func_calls)}, 'total_stepping':self.total_stepping,
                            'comparisons':{'total_state_comparison':self.total_state_comparison, 
                            'real_state_comparison':self.real_state_comparison,
                            'total_var_comparison':self.total_var_comparison}}

        self.general_info = {'bin':{'bin_name':self.bin_name, 'cat_name':self.cat_name, 'p_name':self.p_name,
                            'o_name':self.o_name, 'comp_name':self.comp_name, 'opt_level':self.opt_level},
                            'func_name':self.func_name, 'dec_name':self.dec_name}
        self.orig_info = {'bblocks':self.o_bblocks, 'smgr_stash':{'active':self.o_active, 
                        'returned':self.o_returned, 'queue':self.o_queue, 'errored':self.o_errored, 
                        'unconstrained':self.o_unconstrained}}
        self.recomp_info = {'bblocks':self.r_bblocks, 'smgr_stash':{'active':self.r_active,
                        'returned':self.r_returned, 'queue':self.r_queue, 'errored':self.r_errored,
                        'unconstrained':self.r_unconstrained}}
        self.res_info = {'status':self.status, 'result':self.result, 'mem_usage':self.mem_usage, 
                        'analysis_time':self.analysis_time, 'divergence_info':self.divergence_info,
                        'analysis_info':self.analysis_info}
        self.manual_analysis = {'category':None, 'reason':None, 'source_code_path':None, 'decomp_code_path':None}
        self.IOEQ_info = {'IO_result':self.IO_res, 'orig_ret_nums':self.orig_ret_nums, 
                        'recomp_ret_nums':self.recomp_ret_nums, 'orig_ret_unique_nums':self.orig_ret_unique_nums,
                        'recomp_ret_unique_nums':self.recomp_ret_unique_nums, 'unique_orig_vals':self.unique_orig_vals,
                        'unique_recomp_vals':self.unique_recomp_vals, 'orig_diffs':self.orig_diffs,
                        'recomp_diffs':self.recomp_diffs}

        self.log_dict = {'general_info':self.general_info, 'orig_info':self.orig_info,
                        'recomp_info':self.recomp_info, 'res_info':self.res_info, 'IOEQ_info':self.IOEQ_info,
                        'manual_analysis':self.manual_analysis}

#import psutil
#psutil.virtual_memory()[3]/(1024 ** 2) #in GB