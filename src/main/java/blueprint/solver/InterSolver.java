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
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

import java.lang.reflect.Type;
import java.util.*;

public class InterSolver {

    /** The workList queue of the whole program */
    Queue<FunctionNode> workList = new LinkedList<>();

    /** The set of solved functions */
    Set<FunctionNode> solved = new HashSet<>();

    /** The map from function node to its intra-procedural solver */
    Map<FunctionNode, IntraSolver> intraSolvers = new HashMap<>();

    Set<TypeBuilder> allTypes = new HashSet<>();

    /**
     * Following 2 maps are used to store the relationship between HighVariable and TypeBuilder
     */
    Map<TypeBuilder, Set<HighVariable>> typeToVars = new HashMap<>();
    Map<HighVariable, TypeBuilder> varToType = new HashMap<>();

    /** The call graph of the whole program */
    CallGraph cg;

    public InterSolver(CallGraph cg) {
        this.cg = cg;
        buildWorkListTest();
    }


    public void run() {
        while (!workList.isEmpty()) {
            FunctionNode funcNode = workList.poll();
            IntraSolver intraSolver;
            funcNode.decompile();

            // If the function is not a leaf function, we should
            // collect data-flow facts from its callee functions.
            if (!funcNode.isLeaf) {
                Logging.info("Non-leaf function: " + funcNode.value.getName());
                var ctx = mergeCalleeFacts(funcNode);
                intraSolver = new IntraSolver(funcNode, ctx);
            } else {
                Logging.info("Leaf function: " + funcNode.value.getName());
                intraSolver = new IntraSolver(funcNode, null);
            }

            intraSolver.solve();
            intraSolvers.put(funcNode, intraSolver);
            solved.add(funcNode);
        }
    }


    /**
     * Merge the data-flow facts from the callee functions to the current function.
     * @param funcNode the current non-leaf function node
     * @return the merged context
     */
    private Context mergeCalleeFacts(FunctionNode funcNode) {
        Context ctx = new Context();

        mergeToArgs(funcNode, ctx);

        return ctx;
    }


    private void mergeToArgs(FunctionNode funcNode, Context ctx) {
        var highFunc = funcNode.getHighFunction();

        for (var block : highFunc.getBasicBlocks()) {
            var iter = block.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();
                Logging.info("PcodeOp: " + op.toString());

                // If found Call pcodeOp, then we should merge the data-flow facts from the callee function
                if (op.getOpcode() == PcodeOp.CALL) {
                    var calleeAddr = op.getInput(0).getAddress();
                    var calleeNode = cg.getNodebyAddr(calleeAddr);
                    if (!solved.contains(calleeNode)) {
                        Logging.error("Callee function not solved: " + calleeNode.value.getName());
                        continue;
                    }

                    var calleeCtx = intraSolvers.get(calleeNode).getCtx();

                    // Align the callsite's arguments and callee's parameters
                    assert calleeNode.parameters.size() == op.getNumInputs() - 1;
                    for (int inputIdx = 1; inputIdx < op.getNumInputs(); inputIdx++) {
                        var arg = op.getInput(inputIdx).getHigh();
                        var param = calleeNode.parameters.get(inputIdx - 1);
                        // TODO: do merging ...
                        Logging.debug(String.format(
                            "Merging TypeBuilder from %s: %s to %s: %s",
                            calleeNode.value.getName(), param.getName(),
                            funcNode.value.getName(), arg.getSymbol().getName()
                        ));
                    }

                }
            }
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
