package blueprint.solver;

import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.*;

import ghidra.program.model.address.Address;

public class InterSolver {
    Context ctx;

    /** The call graph of the whole program */
    CallGraph cg;

    public InterSolver(CallGraph cg) {
        this.cg = cg;
        this.ctx = new Context(this.cg);
        buildWorkListTest();
    }


    public void run() {
        while (!ctx.workList.isEmpty()) {
            FunctionNode funcNode = ctx.workList.poll();
            funcNode.decompile();
            DecompilerHelper.dumpHighPcode(funcNode.hFunc);

            // If the function is not a leaf function, we should
            // collect data-flow facts from its callee functions.
            if (!funcNode.isLeaf) {
                Logging.info("Non-leaf function: " + funcNode.value.getName());
            } else {
                Logging.info("Leaf function: " + funcNode.value.getName());
            }
            ctx.createIntraContext(funcNode);

            IntraSolver intraSolver = new IntraSolver(funcNode, ctx);
            intraSolver.solve();

            ctx.solvedFunc.add(funcNode);
        }
    }


    /**
     * Build the worklist for intra-procedural solver, the element's order in the worklist is ...
     */
    private void buildWorkList() {
        // TODO: implement algorithm to build worklist which first process the leaf nodes in the call graph
        // TODO: and then process the non-leaf nodes in the call graph hierarchically.
    }

    private void buildWorkListTest() {
        // intersting leaf nodes:
        // network_merge_config_cpv / buffer_truncate / fdevent_sched_close / fdlog_pipes_abandon_pids / config_merge_config_cpv
        // http_response_upgrade_read_body_unknown / mod_scgi_merge_config_cpv / ...

        Address addr = FunctionHelper.getAddress(0x00119249);
        FunctionNode funcNode = cg.getNodebyAddr(addr);
        ctx.workList.add(funcNode);

        addr = FunctionHelper.getAddress(0x00119337);
        funcNode = cg.getNodebyAddr(addr);
        ctx.workList.add(funcNode);

        addr = FunctionHelper.getAddress(0x0011a70a);
        funcNode = cg.getNodebyAddr(addr);
        ctx.workList.add(funcNode);
    }
}
