## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##
import os
from ghidradbg.util import *
from ghidradbg.commands import *

ghidra_trace_connect(os.getenv('GHIDRA_TRACE_RMI_ADDR'))
args = os.getenv('OPT_TARGET_ARGS')
if args:
    args = ' ' + args
ghidra_trace_create(os.getenv('OPT_TARGET_IMG') + args, start_trace=False)
ghidra_trace_start(os.getenv('OPT_TARGET_IMG'))
ghidra_trace_sync_enable()

# TODO: HACK
dbg.wait()

repl()
