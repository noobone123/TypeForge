package typeclay.solver;

import typeclay.base.dataflow.context.InterContext;
import typeclay.base.graph.CallGraph;
import typeclay.base.node.FunctionNode;
import typeclay.utils.*;

import ghidra.program.model.address.Address;

import java.io.File;
import java.util.*;

public class InterSolver {
    InterContext ctx;
    public Generator generator;

    /** The call graph of the whole program */
    CallGraph cg;

    public InterSolver(CallGraph cg) {
        this.cg = cg;
        this.ctx = new InterContext(this.cg);

        /* Start the analysis from a specific function */
        if (Global.startAddress != 0) {
            Logging.info("InterSolver", "Start the analysis from a specific function");
            buildWorkList(cg.getNodebyAddr(FunctionHelper.getAddress(Global.startAddress)));
            return;
        } else {
            buildWorkList(null);
        }
        // TODO: compare the results with and without setTypeAgnosticFunctions
        // TODO: if needed, complete the heuristic to determine the type-agnostic functions
        setTypeAgnosticFunctions();

        Logging.info("InterSolver", String.format("Total meaningful function count in current binary: %d", FunctionHelper.getMeaningfulFunctions().size()));
        Logging.info("InterSolver", String.format("Function count in workList: %d", ctx.workList.size()));
    }


    public void run() {
        checkCallSitesInconsistency();

        while (!ctx.workList.isEmpty()) {
            FunctionNode funcNode = ctx.workList.poll();
            if (!funcNode.isMeaningful || funcNode.isTypeAgnostic) {
                Logging.info("InterSolver", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }

            if (!funcNode.isLeaf) {
                Logging.info("InterSolver", "Non-leaf function: " + funcNode.value.getName());
            } else {
                Logging.info("InterSolver", "Leaf function: " + funcNode.value.getName());
            }

            ctx.createIntraContext(funcNode);
            IntraSolver intraSolver = new IntraSolver(funcNode, ctx, ctx.getIntraContext(funcNode));
            intraSolver.solve();

            ctx.solvedFunc.add(funcNode);
        }

        ctx.collectSkeletons();

        /* try {
            var outputFile = new File(Global.outputDirectory);
            ctx.typeRelationManager.dumpTRG(outputFile);
            ctx.typeRelationManager.dumpEntryToExitPaths(outputFile);
        } catch (Exception e) {
            Logging.error("InterSolver", "Failed to dump TRGInfo: " + e.getMessage());
        } */

        generator = new Generator(ctx.skeletonCollector, ctx.symExprManager);
        generator.run();
        generator.explore();
    }

    public void checkCallSitesInconsistency() {
        // Records the Map of Callee function and its callsites' argument number
        Map<FunctionNode, Set<Integer>> argNum = new HashMap<>();
        // traverse all functions in worklist
        for (var funcNode: ctx.workList) {
            for (var callsite: funcNode.callSites.values()) {
                var callee = cg.getNodebyAddr(callsite.calleeAddr);
                argNum.computeIfAbsent(callee, k -> new HashSet<>()).add(callsite.arguments.size());
                argNum.get(callee).add(callee.parameters.size());
            }
        }

        for (var entry: argNum.entrySet()) {
            var funcNode = entry.getKey();
            var argNums = entry.getValue();
            if (argNums.size() > 1) {
                Logging.warn("InterSolver", "Inconsistent argument number for function: " + funcNode.value.getName());
                var minArgNum = Collections.min(argNums);
                funcNode.isVarArg = true;
                funcNode.fixedParamNum = minArgNum;
            }
        }
    }


    /**
     * Build the worklist for intra-procedural solver, the element's order in the worklist is ...
     */
    private void buildWorkList(FunctionNode root) {
        List<FunctionNode> sortedFuncs = new ArrayList<>();
        Set<FunctionNode> visited = new HashSet<>();

        if (root != null) {
            postOrderTraversal(root, visited, sortedFuncs);
        } else {
            for (var r: cg.roots) {
                var rootNode = cg.getNodebyAddr(r.getEntryPoint());
                if (rootNode == null) {
                    Logging.warn("InterSolver", "Root function not found: " + r.getName());
                    continue;
                }
                postOrderTraversal(rootNode, visited, sortedFuncs);
            }
        }

        for (FunctionNode funcNode : sortedFuncs) {
            if (!FunctionHelper.isMeaningfulFunction(funcNode.value)) {
                Logging.info("InterSolver", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }

            if (!funcNode.initialize()) {
                Logging.warn("InterSolver", "Failed to pre-analyze function: " + funcNode.value.getName());
                continue;
            }
            ctx.workList.add(funcNode);
            Logging.info("InterSolver", "Added function to workList: " + funcNode.value.getName());
        }
    }

    private void postOrderTraversal(FunctionNode node, Set<FunctionNode> visited, List<FunctionNode> sortedFuncs) {
        if (visited.contains(node)) {
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
            ctx.workList.add(funcNode);
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
            funcNode.setTypeAgnostic();
        }
    }
}
