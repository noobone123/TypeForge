package blueprint.solver;

import blueprint.base.CallGraph;
import blueprint.base.FunctionNode;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.FunctionHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;

import java.util.*;

public class InterSolver {

    /** The workList queue of the whole program */
    Queue<FunctionNode> workList;

    /** The call graph of the whole program */
    CallGraph cg;

    Set<TypeBuilder> allTypes;

    /**
     * Following 2 maps are used to store the relationship between HighVariable and TypeBuilder
     */
    Map<TypeBuilder, Set<HighVariable>> typeToVars;
    Map<HighVariable, TypeBuilder> varToType;

    public InterSolver(CallGraph cg) {
        this.workList = new LinkedList<>();
        this.cg = cg;
        allTypes = new HashSet<>();
        typeToVars = new HashMap<>();
        varToType = new HashMap<>();

        buildWorkListTest();
    }


    public void run() {
        while (!workList.isEmpty()) {
            FunctionNode funcNode = workList.poll();
            IntraSolver intraSolver = new IntraSolver(funcNode);
            intraSolver.solve();
            intraSolver.getCtx();
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
        workList.add(funcNode);

        addr = FunctionHelper.getAddress(0x00119337);
        funcNode = cg.getNodebyAddr(addr);
        workList.add(funcNode);
    }
}
