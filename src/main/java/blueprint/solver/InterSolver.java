package blueprint.solver;

import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.*;

import ghidra.program.model.address.Address;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.List;

public class InterSolver {
    Context ctx;

    /** The call graph of the whole program */
    CallGraph cg;

    public InterSolver(CallGraph cg) {
        this.cg = cg;
        this.ctx = new Context(this.cg);

        var addr = FunctionHelper.getAddress(0x00133bd3);
        var startFunc = cg.getNodebyAddr(addr);
        buildWorkList(startFunc);
    }


    public void run() {
        while (!ctx.workList.isEmpty()) {
            FunctionNode funcNode = ctx.workList.poll();
            if (!funcNode.isMeaningful) {
                Logging.info("InterSolver", "Skip non-meaningful function: " + funcNode.value.getName());
                continue;
            }

            funcNode.decompile();
            funcNode.dumpHighPcode();

            // If the function is not a leaf function, we should
            // collect data-flow facts from its callee functions.
            if (!funcNode.isLeaf) {
                Logging.info("InterSolver", "Non-leaf function: " + funcNode.value.getName());
            } else {
                Logging.info("InterSolver", "Leaf function: " + funcNode.value.getName());
            }
            ctx.createIntraContext(funcNode);

            IntraSolver intraSolver = new IntraSolver(funcNode, ctx);
            intraSolver.solve();

            ctx.solvedFunc.add(funcNode);
        }

        ctx.buildConstraints();
        ctx.dumpResults();
    }

    /**
     * Build the worklist for intra-procedural solver, the element's order in the worklist is ...
     */
    private void buildWorkList(FunctionNode root) {
        List<FunctionNode> sortedFuncs = new ArrayList<>();
        Set<FunctionNode> visited = new HashSet<>();

        postOrderTraversal(root, visited, sortedFuncs);

        for (FunctionNode funcNode : sortedFuncs) {
            Logging.info("InterSolver", "Add function to worklist: " + funcNode.value.getName());
            ctx.workList.add(funcNode);
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
}
