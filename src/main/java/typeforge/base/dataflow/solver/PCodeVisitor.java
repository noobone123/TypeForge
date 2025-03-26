package typeforge.base.dataflow.solver;

import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.KSet;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.node.FunctionNode;
import typeforge.utils.DecompilerHelper;
import typeforge.utils.Global;
import typeforge.utils.HighSymbolHelper;
import typeforge.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;

import java.util.*;

import static typeforge.utils.DecompilerHelper.getSigned;

public class PCodeVisitor {

    public FunctionNode funcNode;
    public IntraSolver intraSolver;
    public NMAEManager exprManager;

    /** The workList queue of current function */
    public LinkedList<PcodeOpAST> workList = new LinkedList<>();

    /** If trace all generated expressions during the abstract interpretation */
    // TODO: maybe tracing only user-specified highSymbol in the future
    private boolean traceAllExprs = false;

    public PCodeVisitor(FunctionNode funcNode, IntraSolver intraSolver, boolean traceAllExprs) {
        this.funcNode = funcNode;
        this.intraSolver = intraSolver;
        this.traceAllExprs = traceAllExprs;
        this.exprManager = intraSolver.exprManager;
    }

    /**
     * Prepare the PCodeVisitor for running on-demand data-flow analysis.
     * In detail:
     * 1. we need to collect the candidate highSymbol's corresponding varnodes and mark them as interested varnodes.
     * 2. initialize the dataFlowFacts using the interested varnodes
     * 2. initialize the workList
     */
    public void prepare() {
        // initialize the workList
        for (var bb: funcNode.hFunc.getBasicBlocks()) {
            var iter = bb.getIterator();
            while (iter.hasNext()) {
                PcodeOp op = iter.next();
                workList.add((PcodeOpAST) op);
            }
        }
    }

    /**
     * Run the on-demand data-flow analysis.
     */
    public void run() {
        while (!workList.isEmpty()) {
            var pcode = workList.poll();
            var opCode = pcode.getOpcode();

            switch (opCode) {
                case PcodeOp.INT_ADD, PcodeOp.INT_SUB -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleAddOrSub(pcode);
                }
                case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.SUBPIECE -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleAssign(pcode);
                }
                case PcodeOp.PTRADD -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handlePtrAdd(pcode);
                }
                case PcodeOp.PTRSUB -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handlePtrSub(pcode);
                }
                case PcodeOp.MULTIEQUAL -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleMultiEqual(pcode);
                }
                case PcodeOp.INT_ZEXT -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleIntZext(pcode);
                }
                case PcodeOp.INT_SEXT -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleIntSext(pcode);
                }
                case PcodeOp.INT_MULT -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleIntMult(pcode);
                }
                case PcodeOp.LOAD -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleLoad(pcode);
                }
                case PcodeOp.STORE -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleStore(pcode);
                }
                case PcodeOp.CALL -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleCall(pcode);
                }
                case PcodeOp.RETURN -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleReturn(pcode);
                }
                case PcodeOp.CALLIND -> {
                    Logging.debug("PCodeVisitor", getPCodeRepresentation(pcode));
                    handleINDCall(pcode);
                }
            }
        }
    }

    /**
     * If parameter is an ADD or SUB operation, we can calculate the new offset
     * But remember, only varnode_1 = varnode_0 + const is not enough to prove that
     * varnode_0 is a base address of structure.
     * For example:
     * b = a + 4 is just a simple arithmetic operation, it does not mean that `a` is a base address of a structure.
     * But if there is a load/store operation like:
     * c = *(a + 4) or *(a + 4) = c, then we can say that `a` is a base address of a structure.
     * @param pcodeOp the PCodeOpAST
     */
    private void handleAddOrSub(PcodeOpAST pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        Varnode output = pcodeOp.getOutput();

        if (!intraSolver.isTracedVn(inputs[0])) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[0]));
            return;
        }

        var inputFact_0 = intraSolver.getDataFlowFacts(inputs[0]);
        assert inputFact_0 != null;

        if (inputs[1].isConstant()) {
            for (var symExpr: inputFact_0) {
                var delta = (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new NMAEManager.Builder().constant(delta).build();
                    var newExpr = exprManager.add(symExpr, deltaSym);
                    if (newExpr != null) {
                        intraSolver.updateDataFlowFacts(output, newExpr);
                    }
                }
            }
        } else {
            if (!intraSolver.isTracedVn(inputs[1])) {
                Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[1]));
                return;
            }
            var inputFact_1 = intraSolver.getDataFlowFacts(inputs[1]);
            for (var symExpr: inputFact_0) {
                for (var symExpr_1: inputFact_1) {
                    var newExpr = exprManager.add(symExpr, symExpr_1);
                    if (newExpr != null) {
                        intraSolver.updateDataFlowFacts(output, newExpr);
                    }
                }
            }
        }
    }


    private void handleAssign(PcodeOp pcodeOp) {
        var inputVn = pcodeOp.getInput(0);
        var outputVn = pcodeOp.getOutput();

        if (!intraSolver.isTracedVn(inputVn)) {
            return;
        }

        var inputFact = intraSolver.getDataFlowFacts(inputVn);

        // If output has already held symbolExpr, we can update the symbol alias map
        var outputFacts = intraSolver.getDataFlowFacts(outputVn);
        for (var inputSymExpr: inputFact) {
            if (outputFacts != null) {
                for (var outputSymExpr: outputFacts) {
                    intraSolver.addIntraTFGEdges(inputSymExpr, outputSymExpr, TypeFlowGraph.EdgeType.DATAFLOW);
                }
            }
            intraSolver.updateDataFlowFacts(outputVn, inputSymExpr);
        }
    }


    /**
     * Handle PTRADD operation. In PTRADD operation,
     * output = input0 + input1 * input2, where input0 is array's base address, input1 is index
     * and input2 is element size.
     * @param pcodeOp The PCodeOp
     */
    private void handlePtrAdd(PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();

        if (!intraSolver.isTracedVn(inputs[0])) {
            Logging.debug("PCOdeVisitor", String.format("%s is not traced", inputs[0]));
            return;
        }

        var input0Fact = intraSolver.getDataFlowFacts(inputs[0]);

        if (inputs[1].isConstant() && inputs[2].isConstant()) {
            for (var symExpr: input0Fact) {
                var delta = getSigned(inputs[1]) * getSigned(inputs[2]);
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new NMAEManager.Builder().constant(delta).build();
                    var newExpr = exprManager.add(symExpr, deltaSym);
                    if (newExpr != null) {
                        intraSolver.updateDataFlowFacts(pcodeOp.getOutput(), newExpr);
                    }
                }
            }
        }
        // inputs[1] is index and inputs[2] is element size
        else if (!inputs[1].isConstant() && inputs[2].isConstant()) {
            if (!intraSolver.isTracedVn(inputs[1])) {
                Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[1]));
                return;
            }
            var scaleValue = getSigned(inputs[2]);
            if (!OffsetSanityCheck(scaleValue)) {
                Logging.debug("PCodeVisitor", String.format("Scale value %d is not valid", scaleValue));
                return;
            }
            var scaleExpr = new NMAEManager.Builder().constant(scaleValue).build();
            for (var symExpr: input0Fact) {
                var indexFacts = intraSolver.getDataFlowFacts(inputs[1]);
                for (var indexExpr: indexFacts) {
                    var newIndexScale = exprManager.multiply(indexExpr, scaleExpr);
                    if (newIndexScale != null) {
                        var newExpr = exprManager.add(symExpr, newIndexScale);
                        if (newExpr != null) {
                            intraSolver.updateDataFlowFacts(pcodeOp.getOutput(), newExpr);
                        }
                    }
                }
            }
        }
        else {
            Logging.warn("PCodeVisitor", String.format("%s + %s * %s can not resolve", inputs[0], inputs[1], inputs[2]));
        }
    }

    /**
     * A PTRSUB performs the simple pointer calculation, input0 + input1
     * Input0 is a pointer to the beginning of the structure, and input1 is a byte offset to the subcomponent.
     * As an operation, PTRSUB produces a pointer to the subcomponent and stores it in output.
     * @param pcodeOp The PCodeOp
     */
    private void handlePtrSub(PcodeOp pcodeOp) {
        Varnode[] inputs = pcodeOp.getInputs();
        var base = inputs[0];
        var offset = inputs[1];
        NMAE outputExpr = null;

        if (base.isRegister()) {
            var reg = Global.currentProgram.getRegister(base);
            // may be a reference of a stack-allocated array or structure
            // For Example:
            // 114_(unique, 0x3200, 8)[noHighSym], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16700_(const, 0xffffffffffffff58, 8)[local_a8]
            // 133_(unique, 0x3200, 8)[local_28], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16702_(const, 0xffffffffffffff58, 8)[local_a8]
            // Where `local_a8` is stack-allocated composite type 133_(unique, 0x3200, 8) and 114_(unique, 0x3200, 8) are actually the same symbol,
            //      but ghidra internal can not resolve it, so we manually recover it
            // Based on the design of TFG, `local_a8` should be represented as a `&local_a8` in the TFG
            if (reg.getName().equals("RSP")) {
                // local symbol
                if (offset.getHigh().getSymbol() != null) {
                    var sym = offset.getHigh().getSymbol();
                    outputExpr = new NMAEManager.Builder().rootSymbol(sym).build();
                    outputExpr = exprManager.reference(outputExpr);
                } else {
                    Logging.warn("PCodeVisitor", String.format("PtrSub handler found an unresolved variable %s", pcodeOp));
                    return;
                }
            }
            else {
                Logging.warn("PCodeVisitor", String.format("PtrSub handler can not resolve other base register %s", reg.getName()));
            }
        }
        // In this case, base is a constant, which means it may be a global symbol
        else if (base.isConstant() && base.getOffset() == 0 && offset.isConstant()) {
            // Global symbol
            var sym = offset.getHigh().getSymbol();
            outputExpr = new NMAEManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(sym), sym).build();
            outputExpr = exprManager.reference(outputExpr);
        }
        // if base is a traced varnode, means it's a fieldAccess of a structure
        else if (intraSolver.isTracedVn(base) && offset.isConstant()) {
            var baseExprs = intraSolver.getDataFlowFacts(base);
            var offsetValue = getSigned(offset);
            if (OffsetSanityCheck(offsetValue)) {
                var offsetExpr = new NMAEManager.Builder().constant(offsetValue).build();
                for (var baseExpr: baseExprs) {
                    outputExpr = exprManager.add(baseExpr, offsetExpr);
                }
            }
        }
        else {
            Logging.warn("PCodeVisitor", String.format("PtrSub handler can not resolve %s", base));
            return;
        }

        if (outputExpr != null) {
            var leftExprs = intraSolver.getDataFlowFacts(pcodeOp.getOutput());
            if (leftExprs != null) {
                for (var leftExpr : leftExprs) {
                    intraSolver.addIntraTFGEdges(outputExpr, leftExpr, TypeFlowGraph.EdgeType.DATAFLOW);
                }
            }
            intraSolver.updateDataFlowFacts(pcodeOp.getOutput(), outputExpr);
        } else {
            Logging.warn("PCodeVisitor", String.format("PtrSub handler can not resolve %s", pcodeOp));
        }
    }


    private void handleMultiEqual(PcodeOp pcodeOp) {
        var output = pcodeOp.getOutput();
        var inputs = pcodeOp.getInputs();

        if (output.getHigh() != null && output.getHigh().getSymbol() != null) {
            var highSym = output.getHigh().getSymbol();
            if (!highSym.isGlobal()) {
                intraSolver.updateDataFlowFacts(output, new NMAEManager.Builder().rootSymbol(highSym).build());
            } else {
                intraSolver.updateDataFlowFacts(output, new NMAEManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(highSym), highSym).build());
            }
        } else {
            for (var input : inputs) {
                intraSolver.mergeDataFlowFacts(input, output, false);
            }
        }

    }


    private void handleIntZext(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(0);
        var output = pcodeOp.getOutput();

        if (!intraSolver.isTracedVn(input)) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", input));
            return;
        }

        var inputFacts = intraSolver.getDataFlowFacts(input);
        for (var symExpr : inputFacts) {
            // TODO: IntZext need add constraint ?
            intraSolver.updateDataFlowFacts(output, symExpr);
        }
    }


    private void handleIntSext(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(0);
        var output = pcodeOp.getOutput();

        if (!intraSolver.isTracedVn(input)) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", input));
            return;
        }

        var inputFacts = intraSolver.getDataFlowFacts(input);
        for (var symExpr : inputFacts) {
            // TODO: IntSext need add constraint ?
            intraSolver.updateDataFlowFacts(output, symExpr);
        }
    }

    private void handleIntMult(PcodeOp pcodeOp) {
        var output = pcodeOp.getOutput();
        var input0 = pcodeOp.getInput(0);
        var input1 = pcodeOp.getInput(1);

        if (!intraSolver.isTracedVn(input0) && !intraSolver.isTracedVn(input1)) {
            Logging.debug("PCodeVisitor", String.format("both %s * %s is not traced", input0, input1));
            return;
        }

        // TODO: handle the case where input0 or input1 is not constant
        if (!input0.isConstant() && !input1.isConstant()) {
            Logging.warn("PCodeVisitor", String.format("%s * %s can not resolve", input0, input1));
            return;
        }

        KSet<NMAE> inputFacts;
        long size = 0;
        if (input0.isConstant()) {
            inputFacts = intraSolver.getDataFlowFacts(input1);
            size = getSigned(input0);
        } else {
            inputFacts = intraSolver.getDataFlowFacts(input0);
            size = getSigned(input1);
        }

        if (OffsetSanityCheck(size)) {
            var sizeExpr = new NMAEManager.Builder().constant(size).build();
            for (var symExpr : inputFacts) {
                var newExpr = exprManager.multiply(symExpr, sizeExpr);
                if (newExpr != null) {
                    intraSolver.updateDataFlowFacts(output, newExpr);
                }
            }
        }
    }

    /**
     * If pcodeOp is a LOAD or STORE operation, it's possible that the offset is a field of a structure.
     * For instance:
     * <p>
     *     <code> varnode_1 = *(varnode_0 + 4) </code>
     *     <code> *(varnode_1 + 4) = varnode_2 </code>
     * </p>
     * And type of this field is determined by the type of loaded/stored varnode's type.
     * However, be aware that some case might be loaded/store into a context even if they aren't
     * fields of a structure.
     * For instance:
     * <p>
     *     <code> varnode_1 = *varnode_0 </code>
     *     <code> *varnode_1 = varnode_2 </code>
     * </p>
     * Such cases can be excluded in later stages.
     * @param pcodeOp The PCodeOp
     */
    private void handleLoad(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(1);
        var output = pcodeOp.getOutput();

        if (!intraSolver.isTracedVn(input)) {
            Logging.debug("PCodeVisitor", "Load addr is not interested: " + input);
            return;
        }

        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);
        var leftValueExprs = intraSolver.getDataFlowFacts(output);
        var loadAddrExprs = intraSolver.getDataFlowFacts(input);
        for (var loadAddrExpr : loadAddrExprs) {
            var loadedValueExpr = exprManager.dereference(loadAddrExpr);

            intraSolver.addFieldAccessExpr(loadedValueExpr, pcodeOp, outDT, AccessPoints.AccessType.LOAD, funcNode.value);

            // If Loaded value is not null, means:
            // a = *(b), so set a and *(b) as type alias
            if (leftValueExprs != null) {
                for (var leftValueExpr : leftValueExprs) {
                    Logging.debug("PCodeVisitor", String.format("Loaded varnode has already held %s, set type alias of %s and %s", leftValueExpr, loadedValueExpr, leftValueExpr));
                    intraSolver.addIntraTFGEdges(loadedValueExpr, leftValueExpr, TypeFlowGraph.EdgeType.DATAFLOW);
                }
            }

            intraSolver.updateDataFlowFacts(output, loadedValueExpr);
        }
    }

    /**
     * Same as handleLoad, but for STORE operation
     */
    private void handleStore(PcodeOp pcodeOp) {
        // the slot index of cur.varnode is 1, which means this varnode
        // represent the memory location to be stored
        var storedAddrVn = pcodeOp.getInput(1);
        var rightValueVn = pcodeOp.getInput(2);

        if (!intraSolver.isTracedVn(storedAddrVn)) {
            Logging.debug("PCodeVisitor", "Store address is not interested: " + storedAddrVn);
            return;
        }

        var rightValueExprs = intraSolver.getDataFlowFacts(rightValueVn);
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(pcodeOp.getInput(2));

        for (var storedAddrExpr : intraSolver.getDataFlowFacts(storedAddrVn)) {
            var storedValueExpr = exprManager.dereference(storedAddrExpr);
            intraSolver.addFieldAccessExpr(storedValueExpr, pcodeOp, storedValueDT, AccessPoints.AccessType.STORE, funcNode.value);
            if (rightValueExprs != null) {
                for (var rightValueExpr : rightValueExprs) {
                    Logging.debug("PCodeVisitor", String.format("Stored varnode has already held %s, set type alias of %s and %s", rightValueExpr, storedValueExpr, rightValueExpr));
                    intraSolver.addIntraTFGEdges(rightValueExpr, storedValueExpr, TypeFlowGraph.EdgeType.DATAFLOW);
                }
            }
        }
    }

    private void handleINDCall(PcodeOp pcodeOp) {
        var indirectCallVn = pcodeOp.getInput(0);
        if (!intraSolver.isTracedVn(indirectCallVn)) {
            Logging.debug("PCodeVisitor", "Indirect Call is not interested: " + indirectCallVn);
            return;
        }

        var indirectCallFacts = intraSolver.getDataFlowFacts(indirectCallVn);
        for (var symExpr : indirectCallFacts) {
            exprManager.addExprAttribute(symExpr, NMAE.Attribute.CODE_PTR);
        }
    }


    private void handleReturn(PcodeOp pcodeOp) {
        for (var retVn : pcodeOp.getInputs()) {
            if (!intraSolver.isTracedVn(retVn)) {
                Logging.debug("PCodeVisitor", "Return value is not interested: " + retVn);
                continue;
            }

            var retFacts = intraSolver.getDataFlowFacts(retVn);
            for (var retExpr : retFacts) {
                intraSolver.setReturnExpr(retExpr);
                exprManager.addExprAttribute(retExpr, NMAE.Attribute.RETURN);
                Logging.debug("PCodeVisitor", "Setting Return Value: " + retExpr);
            }
        }
    }

    private void handleCall(PcodeOp pcodeOp) {
        var callSite = funcNode.callSites.get(pcodeOp);
        var argToFacts = new HashMap<Varnode, KSet<NMAE>>();

        for (var arg: callSite.arguments) {
            // We consider constant callsite arguments because it's useful for following analysis.
            if (arg.isConstant()) {
                Logging.debug("PCodeVisitor",
                        String.format("Argument %s is a constant.", arg));

                var constExpr = new NMAEManager.Builder().constant(getSigned(arg)).build();
                intraSolver.updateDataFlowFacts(arg, constExpr);
            }

            if (!intraSolver.isTracedVn(arg)) {
                if (arg.isUnique()) {
                    Logging.debug("PCodeVisitor",
                            String.format("Argument %s maybe an unique string.", arg));
                }

                Logging.warn("PCodeVisitor", "Argument is not interested: " + arg);
                continue;
            }

            var argFacts = intraSolver.getDataFlowFacts(arg);
            argToFacts.put(arg, argFacts);

            for (var argExpr : argFacts) {
                exprManager.addExprAttribute(argExpr, NMAE.Attribute.ARGUMENT);
            }
        }

        // Update the bridgeInfo for the arguments / parameters
        intraSolver.bridgeInfo.put(callSite, argToFacts);

        // handle ReturnValue's receiver
        if (!callSite.hasReceiver()) {
            return;
        }

        var receiverVn = callSite.receiver;
        var receiverFacts = intraSolver.getDataFlowFacts(receiverVn);

        if (receiverFacts != null) {
            intraSolver.bridgeInfo.computeIfAbsent(
                    callSite,
                    k -> new HashMap<>()
            ).put(receiverVn, receiverFacts);
        } else {
            if (receiverVn.getHigh() != null && receiverVn.getHigh().getSymbol() != null) {
                Logging.warn("PCodeVisitor", String.format("Receiver %s is not traced, maybe merged variables", receiverVn.getHigh().getName()));
            }
            else {
                var receiverLongDescend = receiverVn.getLoneDescend();
                var newReceiverVn = receiverLongDescend.getOutput();
                var newReceiverFacts = intraSolver.getDataFlowFacts(newReceiverVn);
                if (newReceiverFacts != null) {
                    callSite.receiver = newReceiverVn;
                    intraSolver.bridgeInfo.computeIfAbsent(
                            callSite,
                            k -> new HashMap<>()
                    ).put(newReceiverVn, newReceiverFacts);
                } else {
                    Logging.warn("PCodeVisitor", "????????????????????");
                }
            }
        }
    }

    private boolean checkIfHoldsCompositeType(NMAE expr) {
        return expr.hasAttribute(NMAE.Attribute.ARRAY) ||
                expr.hasAttribute(NMAE.Attribute.STRUCT) ||
                expr.hasAttribute(NMAE.Attribute.UNION);
    }

    /**
     * Check if the offset is sane to be a structure offset
     * @param offset the offset
     * @return true if the offset is sane
     */
    private boolean OffsetSanityCheck(long offset) {
        // TODO: 0x2000 is a reasonable limit for a structure ?
        if (offset < 0) {
            return false;
        }
        return offset <= 0x2000;
    }


    private String getPCodeRepresentation(PcodeOp pcodeOp) {
        StringBuilder result = new StringBuilder();
        VarnodeAST outVn = (VarnodeAST) pcodeOp.getOutput();
        if (outVn != null) {
            result.append(DecompilerHelper.getVarnodeString(outVn));
        } else {
            result.append("---");
        }

        result.append("  ").append(pcodeOp.getMnemonic());
        //Output Pcode op's input Varnodes
        for (int i = 0; i < pcodeOp.getNumInputs(); ++i) {
            result.append("  ").append(DecompilerHelper.getVarnodeString((VarnodeAST)pcodeOp.getInput(i)));
        }

        return result.toString();
    }
}
