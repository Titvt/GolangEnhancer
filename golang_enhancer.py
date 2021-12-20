# -*- coding:utf-8 -*-

import string

import idc
from idaapi import *

desc = '''
Golang Enhancer V1.0
GitHub: https://github.com/Titvt/GolangEnhancer/
'''

logo = r'''
 _____           _                              _____           _                                           
|  __ \         | |                            |  ___|         | |                                          
| |  \/   ___   | |   __ _   _ __     __ _     | |__    _ __   | |__     __ _   _ __     ___    ___   _ __  
| | __   / _ \  | |  / _` | | '_ \   / _` |    |  __|  | '_ \  | '_ \   / _` | | '_ \   / __|  / _ \ | '__| 
| |_\ \ | (_) | | | | (_| | | | | | | (_| |    | |___  | | | | | | | | | (_| | | | | | | (__  |  __/ | |    
 \____/  \___/  |_|  \__,_| |_| |_|  \__, |    \____/  |_| |_| |_| |_|  \__,_| |_| |_|  \___|  \___| |_|    
                                      __/ |                                                                 
                                     |___/                                                                        
'''

str_execute_failed = '''
执行失败：该程序不是一个带符号的Golang程序。
Execute failed: This program is not a Golang program with symbols.
'''

str_golang_version = '''
Golang版本：{0}
Golang Version: {0}
'''

str_result = '''
执行成功：{0}个函数已恢复，{1}个函数未恢复。
Execute succeeded: {0} functions have been recovered, {1} functions have not been recovered.
'''

argv = {
    0: '_QWORD __usercall {}<rax>();',
    1: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>);',
    2: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>);',
    3: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>);',
    4: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>, _QWORD arg4<rdi>);',
    5: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>, _QWORD arg4<rdi>, _QWORD arg5<rsi>);',
    6: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>, _QWORD arg4<rdi>, _QWORD arg5<rsi>, _QWORD arg6<r8>);',
    7: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>, _QWORD arg4<rdi>, _QWORD arg5<rsi>, _QWORD arg6<r8>, _QWORD arg7<r9>);',
    8: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>, _QWORD arg4<rdi>, _QWORD arg5<rsi>, _QWORD arg6<r8>, _QWORD arg7<r9>, _QWORD arg8<r10>);',
    9: '_QWORD __usercall {}<rax>(_QWORD arg1<rax>, _QWORD arg2<rbx>, _QWORD arg3<rcx>, _QWORD arg4<rdi>, _QWORD arg5<rsi>, _QWORD arg6<r8>, _QWORD arg7<r9>, _QWORD arg8<r10>, _QWORD arg9<r11>);',
}


def get_valid_name(name):
    ret = ''

    for i in name:
        if i in string.ascii_letters + string.digits:
            ret += i
        else:
            ret += '_'

    return ret


class GolangEnhancer(plugin_t):
    flags = PLUGIN_MOD + PLUGIN_DRAW + PLUGIN_UNL
    wanted_name = 'Golang Enhancer'
    wanted_hotkey = 'Ctrl+Alt+G'
    comment = 'Golang Enhancer'
    help = desc

    def init(self):
        print(self.help)
        return PLUGIN_OK

    def term(self):
        pass

    def run(self, arg):
        print(logo)

        go_ver = get_name_ea(BADADDR, 'runtime.buildVersion.str')
        if go_ver == BADADDR:
            print(str_execute_failed)
            return

        go_ver = get_strlit_contents(go_ver, -1, STRTYPE_C).decode()[2:]
        print(str_golang_version.format(go_ver))

        fn_def = 0
        fn_und = 0
        for i in range(get_func_qty()):
            func = getn_func(i)
            name = get_valid_name(get_func_name(func.start_ea))
            argc = 0

            insn = insn_t()
            decode_prev_insn(insn, func.end_ea)
            ea = insn.ea

            if idc.print_insn_mnem(ea) == 'jmp' and idc.print_operand(ea, 0) == name:
                while argc < 9:
                    decode_prev_insn(insn, ea)
                    ea = insn.ea

                    if idc.print_insn_mnem(ea) == 'nop':
                        continue

                    if idc.print_insn_mnem(ea) == 'call' and idc.print_operand(ea, 0).startswith('runtime_morestack'):
                        break

                    argc += 1
                fn_def += 1
            else:
                argc = 0
                fn_und += 1

            idc.SetType(func.start_ea, argv[argc].format(name))

        print(str_result.format(fn_def, fn_und))


def PLUGIN_ENTRY():
    return GolangEnhancer()
