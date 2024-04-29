package blueprint.solver;

import blueprint.base.dataflow.TypeBuilder;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.*;

import java.util.*;

import static blueprint.utils.DecompilerHelper.getSigned;

public class InterSolver {

    /** The workList queue of the whole program */
    Queue<FunctionNode> workList = new LinkedList<>();

    /** The set of solved functions */
    Set<FunctionNode> solved = new HashSet<>();

    /** The map from function node to its intra-procedural solver */
    Map<FunctionNode, IntraSolver> funcNodeToIntraSolver = new HashMap<>();

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
            DecompilerHelper.dumpHighPcode(funcNode.hFunc);
            // Logging.info(funcNode.getC());
//            for (var token: funcNode.tokens) {
//                if (token.getText().equals("local_a8")) {
//                    Logging.info("Found local_a8");
//                    Logging.info(String.valueOf(token.getHighSymbol(funcNode.hFunc).getName()));
//                } else if (token.getText().equals(("local_148"))) {
//                    Logging.info("Found local_148");
//                    Logging.info(String.valueOf(token.getHighSymbol(funcNode.hFunc).getName()));
//                }
//            }

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
            funcNodeToIntraSolver.put(funcNode, intraSolver);
            solved.add(funcNode);
        }
    }


    /**
     * Merge the data-flow facts from the callee functions to the current function.
     * @param funcNode the current non-leaf function node
     * @return the merged context
     */
    private Context mergeCalleeFacts(FunctionNode funcNode) {
        Context ctx = new Context(funcNode);

        mergeParamsToArgs(funcNode, ctx);
        // TODO: merge the return value

        return ctx;
    }

    /**
     * Merge the data-flow facts (TypeBuilder) from the callee function's param to the current function's arguments.
     * @param funcNode the current non-leaf function node
     * @param ctx the context to store current data-flow facts
     */
    private void mergeParamsToArgs(FunctionNode funcNode, Context ctx) {
        var highFunc = funcNode.hFunc;

        for (var block : highFunc.getBasicBlocks()) {
            var iter = block.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();

                // If found Call pcodeOp, then we should merge the data-flow facts from the callee function
                if (op.getOpcode() == PcodeOp.CALL) {
                    var calleeAddr = op.getInput(0).getAddress();
                    var calleeNode = cg.getNodebyAddr(calleeAddr);
                    if (!solved.contains(calleeNode)) {
                        Logging.warn("Callee function not solved: " + calleeNode.value.getName());
                        continue;
                    }

                    var calleeSolver = funcNodeToIntraSolver.get(calleeNode);
                    var calleeCtx = calleeSolver.getCtx();

                    // TODO: what if callsite's arguments did not match callee's parameters?
                    assert calleeNode.parameters.size() == op.getNumInputs() - 1;

                    // Align the callsite's arguments and callee's parameters
                    for (int inputIdx = 1; inputIdx < op.getNumInputs(); inputIdx++) {

                        // Merge dataflow facts from parameters to arguments is not easy, because the argument in the callsite may exist in different forms:
                        // callsite case 1: func(a, b)
                        // callsite case 2: func(a+0x10, b), in this case, varnode `a+0x10` has HighVariable without name and has no HighSymbol,
                        //                  in this case, we should merge the data-flow facts to `a` instead of `a+0x10`. So we should find the
                        //                  original HighSymbol `a`.
                        var callSiteArgVn = op.getInput(inputIdx);
                        var resolved = resolveCallSiteArg(callSiteArgVn);
                        if (resolved == null) {
                            Logging.warn("Failed to resolve callsite argument: " + callSiteArgVn);
                            continue;
                        }

                        var to = (HighSymbol) resolved[0];
                        long offset = (long) resolved[1];
                        Logging.debug("Resolved callsite argument: " + to.getName() + " offset: 0x" + Long.toHexString(offset));

                        var from = calleeNode.parameters.get(inputIdx - 1);

                        if (ctx.updateTypeBuilderFromCallee(calleeCtx, from, to, offset)) {
                            Logging.debug(String.format(
                                    "Merge TypeBuilder from %s: %s to %s: %s + 0x%x",
                                    calleeNode.value.getName(), from.getName(),
                                    funcNode.value.getName(), to.getName(), offset
                            ));
                        } else {
                            Logging.error(String.format(
                                    "Failed to merge TypeBuilder from %s: %s to %s: %s + 0x%x",
                                    calleeNode.value.getName(), from.getName(),
                                    funcNode.value.getName(), to.getName(), offset
                            ));
                        }
                    }
                }
            }
        }
    }


    /**
     * Resolve the HighSymbol from the Varnode in the callsite to its original HighSymbol in the callee function.
     * For example:
     * func(a+0x10, b) should return [HighSymbol(a), 0x10]
     * @param arg the Varnode in the callsite
     * @return the corresponding original HighSymbol in the callee function and the offset between the original HighSymbol and the Varnode
     */
    private Object[] resolveCallSiteArg(Varnode arg) {
        var highVariable = arg.getHigh();
        var highSymbol = highVariable.getSymbol();
        if (!highVariable.getName().equals("UNNAMED") && highSymbol != null) {
            return new Object[]{highSymbol, 0L};
        }

        var defPCode = arg.getDef();
        if (defPCode == null) {
            return null;
        }

        assert defPCode.getOutput() == arg;
        switch (defPCode.getOpcode()) {
            case PcodeOp.PTRADD:
                Varnode[] inputs = defPCode.getInputs();
                if (!inputs[1].isConstant() || !inputs[2].isConstant()) {
                    Logging.warn("PTRADD with non-constant offset, skip resolving");
                    return null;
                }
                return new Object[]{inputs[0].getHigh().getSymbol(), getSigned(inputs[1]) * getSigned(inputs[2])};
        }

        return null;
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
//
//        addr = FunctionHelper.getAddress(0x0011a70a);
//        funcNode = cg.getNodebyAddr(addr);
//        workList.add(funcNode);
    }
}
