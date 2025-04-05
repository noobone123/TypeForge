package typeforge.analyzer;

import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import typeforge.base.dataflow.solver.InterSolver;
import typeforge.base.graph.CallGraph;
import typeforge.base.node.FunctionNode;
import typeforge.base.parallel.PrepareFunctionNodeCallback;
import typeforge.utils.*;

import ghidra.program.model.address.Address;

import java.util.*;

public class TypeAnalyzer {
    InterSolver interSolver;
    public Generator generator;

    /** The call graph of the whole program */
    CallGraph cg;

    public TypeAnalyzer(CallGraph cg) {
        this.cg = cg;
        this.interSolver = new InterSolver(this.cg);

        /* Start the analysis from a specific function */
        if (Global.startAddress != 0) {
            Logging.debug("TypeAnalyzer", "Start the analysis from a specific function");
            prepareAnalyze(cg.getNodebyAddr(FunctionHelper.getAddress(Global.startAddress)));
            return;
        }
        /* Analysis all functions in the binary */
        else {
            prepareAnalyze(null);
        }

        // TODO: just for testing
        // setTypeAgnosticFunctions();

        Logging.debug("TypeAnalyzer", String.format("Total meaningful function count in current binary: %d", FunctionHelper.getMeaningfulFunctions().size()));
        Logging.debug("TypeAnalyzer", String.format("Function count in workList: %d", interSolver.workList.size()));
    }

    /**
     * Prepare for the analysis, including:
     *  1. Sort the functions in post-order
     *  2. Decompiling the functions to get HighSymbols for further analysis
     *  3. Add the functions to the workList
     *
     * @param root The root function to start the analysis,
     *             if null, analyze all functions in the binary
     */
    private void prepareAnalyze(FunctionNode root) {
        Global.prepareAnalysisBeginTime = System.currentTimeMillis();

        List<FunctionNode> sortedFuncs = new ArrayList<>();
        Set<FunctionNode> visited = new HashSet<>();

        // Sort the functions in post-order
        if (root != null) {
            postOrderTraversal(root, visited, sortedFuncs);
        } else {
            for (var r: cg.roots) {
                var rootNode = cg.getNodebyAddr(r.getEntryPoint());
                if (rootNode == null) {
                    Logging.warn("TypeAnalyzer", "Root function not found: " + r.getName());
                    continue;
                }
                postOrderTraversal(rootNode, visited, sortedFuncs);
            }
        }

        // Decompiling the functions
        var decompileSet = new HashSet<Function>();
        var addrToFuncNode = new HashMap<Address, FunctionNode>();

        for (var funcNode: sortedFuncs) {
            if (!FunctionHelper.isMeaningfulFunction(funcNode.value)) {
                Logging.debug("TypeAnalyzer", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }
            decompileSet.add(funcNode.value);
            addrToFuncNode.put(
                    funcNode.value.getEntryPoint(),
                    funcNode
            );
            interSolver.workList.add(funcNode);
            Logging.debug("TypeAnalyzer", "Added function to workList: " + funcNode.value.getName());
        }

        // Decompile the functions in parallel
        var callback = new PrepareFunctionNodeCallback(
                Global.currentProgram,
                (ifc) -> {
                    ifc.toggleCCode(false);
                    // PCodeSyntaxTree must be enabled to get HighSymbol
                    ifc.toggleSyntaxTree(true);
                },
                addrToFuncNode
        );

        try {
            ParallelDecompiler.decompileFunctions(callback, decompileSet, TaskMonitor.DUMMY);
        } catch (Exception e) {
            Logging.error("TypeAnalyzer", "Could not decompile functions with ParallelDecompiler");
        } finally {
            callback.dispose();
        }

        var decompiledFuncCnt = callback.decompileCount;
        Logging.info("TypeAnalyzer", String.format("Decompiled function count: %d", decompiledFuncCnt));

        // Do some post-decompile preparation
        for (var funcNode: sortedFuncs) {
            // Fix function prototype
            if (funcNode.needFixPrototype) {
                var success = funcNode.fixFunctionProto();
                if (!success) {
                    Logging.error("TypeAnalyzer", "Failed to fix function prototype: " + funcNode.value.getName());
                } else {
                    Logging.debug("TypeAnalyzer", "Fixed function prototype: " + funcNode.value.getName());
                }
            }
        }

        Global.prepareAnalysisEndTime = System.currentTimeMillis();
    }

    /**
     * Run the Type Analysis,
     * building Whole-program Type Flow Graph and constructing the final type constraints
     */
    public void run() {
        markVarArgFunctions();

        // Intra-procedural analysis, build TFG of each function
        // TODO: intra-procedural analysis in parallel
        var workListCopy = new LinkedList<>(interSolver.workList);

        while (!workListCopy.isEmpty()) {
            FunctionNode funcNode = workListCopy.poll();
            if (!funcNode.isMeaningful) {
                Logging.debug("TypeAnalyzer", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }

            var intraSolver = interSolver.createIntraSolver(funcNode);
            intraSolver.solve();

            interSolver.visitedFunc.add(funcNode);
        }

        interSolver.buildWholeProgramTFG();
        interSolver.typeHintPropagation();

        generator = new Generator(interSolver.typeHintCollector, interSolver.exprManager);
        generator.run();
        generator.explore();
    }

    /**
     * Due to decompiler's limitation, some functions may have inconsistent argument number at different callsites.
     * So we need to mark these functions as vararg functions.
     * And we will use the minimum argument number as the fixed parameter number in the subsequent analysis.
     */
    public void markVarArgFunctions() {
        // A map to store the function and the number of arguments of its callsites
        Map<FunctionNode, Set<Integer>> argNum = new HashMap<>();
        // traverse all functions in workList
        for (var funcNode: interSolver.workList) {
            for (var callsite: funcNode.callSites.values()) {
                var callee = cg.getNodebyAddr(callsite.calleeAddr);
                if (callee == null) continue;
                argNum.computeIfAbsent(callee, k -> new HashSet<>()).add(callsite.arguments.size());
                argNum.get(callee).add(callee.parameters.size());
            }
        }

        for (var entry: argNum.entrySet()) {
            var funcNode = entry.getKey();
            var argNums = entry.getValue();
            if (argNums.size() > 1) {
                Logging.trace("TypeAnalyzer", "Inconsistent argument number for function: " + funcNode.value.getName());
                var minArgNum = Collections.min(argNums);
                funcNode.isVarArg = true;
                funcNode.fixedParamNum = minArgNum;
            }
        }
    }




    private void postOrderTraversal(FunctionNode node, Set<FunctionNode> visited, List<FunctionNode> sortedFuncs) {
        if (visited.contains(node)) {
            return;
        }
        if (node == null) {
            return;
        }
        visited.add(node);

        for (FunctionNode callee : cg.getCallees(node)) {
            postOrderTraversal(callee, visited, sortedFuncs);
        }
        sortedFuncs.add(node);
    }

    private void buildWorkListTest() {
        // intersting leaf nodes:
        // network_merge_config_cpv / buffer_truncate / fdevent_sched_close / fdlog_pipes_abandon_pids / config_merge_config_cpv
        // http_response_upgrade_read_body_unknown / mod_scgi_merge_config_cpv / ...
        Address addr;
        FunctionNode funcNode;

        var addrList = List.of(
            0x00119249, // network_merge_config_cpv
            0x00119337, // network_merge_config
            0x0012f820, // buffer_realloc
            0x0012f905, // buffer_alloc_replace
            0x0012fc86, // buffer_copy_string_len
            0x00133b7c, // log_buffer_tstr
                0x0012f978, // buffer_string_prepare_copy
                0x0012fb09, // buffer_extend
                0x0012fd8f, // buffer_append_str2
                0x00130203, // utostr
                0x00130485, // li_utostrn
                0x001339f7, // buffer_clen
                0x00133bd3, // log_buffer_timestamp
            0x00133ab0, // buffer_clear
                0x0012fe84, // buffer_append_iovec
                0x00133d4b, // log_buffer_prefix
            0x0013401b, // log_buffer_prepare
            0x0013418f, // log_va_list
            0x00134309, // log_error
            0x0011b7de, // network_write_init
            0x0011a70a  // network_init
        );

        for (var a : addrList) {
            addr = FunctionHelper.getAddress(a);
            funcNode = cg.getNodebyAddr(addr);
            interSolver.workList.add(funcNode);
        }
    }


    public void setTypeAgnosticFunctions() {
        var addrList = List.of(
                0x0015c04e, // ck_realloc_u32
                0x0015bffc,  // ck_calloc
                0x0015bfb5  // ck_malloc
        );

        for (var addr: addrList) {
            var funcNode = cg.getNodebyAddr(FunctionHelper.getAddress(addr));
            if (funcNode != null) {
                funcNode.setTypeAgnostic();
            }
        }
    }
}
