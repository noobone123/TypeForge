package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.context.InterContext;
import blueprint.base.dataflow.context.IntraContext;
import blueprint.base.dataflow.typeAlias.TypeAliasGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.DecompilerHelper;
import blueprint.utils.Global;
import blueprint.utils.HighSymbolHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;

import java.util.*;

import static blueprint.utils.DecompilerHelper.getSigned;

public class PCodeVisitor {

    public InterContext interCtx;
    public IntraContext intraCtx;
    public FunctionNode funcNode;
    public SymbolExprManager symExprManager;

    /** The workList queue of current function */
    public LinkedList<PcodeOpAST> workList = new LinkedList<>();

    public PCodeVisitor(FunctionNode funcNode, InterContext interCtx, IntraContext intraCtx) {
        this.funcNode = funcNode;
        this.interCtx = interCtx;
        this.intraCtx = intraCtx;
        symExprManager = intraCtx.symbolExprManager;
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

        if (!intraCtx.isTracedVn(inputs[0])) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[0]));
            return;
        }

        var inputFact_0 = intraCtx.getDataFlowFacts(inputs[0]);
        assert inputFact_0 != null;

        if (inputs[1].isConstant()) {
            for (var symExpr: inputFact_0) {
                var delta = (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new SymbolExprManager.Builder().constant(delta).build();
                    var newExpr = symExprManager.add(symExpr, deltaSym);
                    if (newExpr != null) {
                        intraCtx.updateDataFlowFacts(output, newExpr);
                    }
                }
            }
        } else {
            if (!intraCtx.isTracedVn(inputs[1])) {
                Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[1]));
                return;
            }
            var inputFact_1 = intraCtx.getDataFlowFacts(inputs[1]);
            for (var symExpr: inputFact_0) {
                for (var symExpr_1: inputFact_1) {
                    var newExpr = symExprManager.add(symExpr, symExpr_1);
                    if (newExpr != null) {
                        intraCtx.updateDataFlowFacts(output, newExpr);
                    }
                }
            }
        }
    }


    private void handleAssign(PcodeOp pcodeOp) {
        var inputVn = pcodeOp.getInput(0);
        var outputVn = pcodeOp.getOutput();

        if (!intraCtx.isTracedVn(inputVn)) {
            return;
        }

        var inputFact = intraCtx.getDataFlowFacts(inputVn);

        // If output has already held symbolExpr, we can update the symbol alias map
        var outputFacts = intraCtx.getDataFlowFacts(outputVn);
        for (var inputSymExpr: inputFact) {
            if (outputFacts != null) {
                for (var outputSymExpr: outputFacts) {
                    interCtx.addTypeAliasRelation(inputSymExpr, outputSymExpr, TypeAliasGraph.EdgeType.DATAFLOW);
                }
            }
            intraCtx.updateDataFlowFacts(outputVn, inputSymExpr);
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

        if (!intraCtx.isTracedVn(inputs[0])) {
            Logging.debug("PCOdeVisitor", String.format("%s is not traced", inputs[0]));
            return;
        }

        var input0Fact = intraCtx.getDataFlowFacts(inputs[0]);

        if (inputs[1].isConstant() && inputs[2].isConstant()) {
            for (var symExpr: input0Fact) {
                var delta = getSigned(inputs[1]) * getSigned(inputs[2]);
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new SymbolExprManager.Builder().constant(delta).build();
                    var newExpr = symExprManager.add(symExpr, deltaSym);
                    if (newExpr != null) {
                        intraCtx.updateDataFlowFacts(pcodeOp.getOutput(), newExpr);
                    }
                }
            }
        }
        // inputs[1] is index and inputs[2] is element size
        else if (!inputs[1].isConstant() && inputs[2].isConstant()) {
            if (!intraCtx.isTracedVn(inputs[1])) {
                Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[1]));
                return;
            }
            var scaleValue = getSigned(inputs[2]);
            if (!OffsetSanityCheck(scaleValue)) {
                Logging.debug("PCodeVisitor", String.format("Scale value %d is not valid", scaleValue));
                return;
            }
            var scaleExpr = new SymbolExprManager.Builder().constant(scaleValue).build();
            for (var symExpr: input0Fact) {
                var indexFacts = intraCtx.getDataFlowFacts(inputs[1]);
                for (var indexExpr: indexFacts) {
                    var newIndexScale = symExprManager.multiply(indexExpr, scaleExpr);
                    if (newIndexScale != null) {
                        var newExpr = symExprManager.add(symExpr, newIndexScale);
                        if (newExpr != null) {
                            intraCtx.updateDataFlowFacts(pcodeOp.getOutput(), newExpr);
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
        SymbolExpr outputExpr = null;

        if (base.isRegister()) {
            var reg = Global.currentProgram.getRegister(base);
            // may be a reference of a local array or a stack structure or a stack array.
            // For Example:
            // 114_(unique, 0x3200, 8)[noHighSym], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16700_(const, 0xffffffffffffff58, 8)[local_a8]
            // 133_(unique, 0x3200, 8)[local_28], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16702_(const, 0xffffffffffffff58, 8)[local_a8]
            // 133_(unique, 0x3200, 8) and 114_(unique, 0x3200, 8) are actually the same symbol, but ghidra internal can not resolve it, so we manually recover it
            // 114_(unique, 0x3200, 8)[noHighSym] has no initial Facts but 133_(unique, 0x3200, 8)[local_28] has initial Facts
            if (reg.getName().equals("RSP")) {
                // local symbol
                if (offset.getHigh().getSymbol() != null) {
                    var sym = offset.getHigh().getSymbol();
                    outputExpr = new SymbolExprManager.Builder().rootSymbol(sym).build();
                    outputExpr = symExprManager.reference(outputExpr);
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
            outputExpr = new SymbolExprManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(sym), sym).build();
            outputExpr = symExprManager.reference(outputExpr);
        }
        // if base is a traced varnode, means it's a fieldAccess of a structure
        else if (intraCtx.isTracedVn(base) && offset.isConstant()) {
            var baseExprs = intraCtx.getDataFlowFacts(base);
            var offsetValue = getSigned(offset);
            if (OffsetSanityCheck(offsetValue)) {
                var offsetExpr = new SymbolExprManager.Builder().constant(offsetValue).build();
                for (var baseExpr: baseExprs) {
                    outputExpr = symExprManager.add(baseExpr, offsetExpr);
                }
            }
        }
        else {
            Logging.warn("PCodeVisitor", String.format("PtrSub handler can not resolve %s", base));
            return;
        }

        if (outputExpr != null) {
            var leftExprs = intraCtx.getDataFlowFacts(pcodeOp.getOutput());
            if (leftExprs != null) {
                for (var leftExpr : leftExprs) {
                    interCtx.addTypeAliasRelation(outputExpr, leftExpr, TypeAliasGraph.EdgeType.DATAFLOW);
                }
            }
            intraCtx.updateDataFlowFacts(pcodeOp.getOutput(), outputExpr);
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
                intraCtx.updateDataFlowFacts(output, new SymbolExprManager.Builder().rootSymbol(highSym).build());
            } else {
                intraCtx.updateDataFlowFacts(output, new SymbolExprManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(highSym), highSym).build());
            }
        } else {
            for (var input : inputs) {
                intraCtx.mergeDataFlowFacts(input, output, false);
            }
        }

    }


    private void handleIntZext(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(0);
        var output = pcodeOp.getOutput();

        if (!intraCtx.isTracedVn(input)) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", input));
            return;
        }

        var inputFacts = intraCtx.getDataFlowFacts(input);
        for (var symExpr : inputFacts) {
            // TODO: IntZext need add constraint ?
            intraCtx.updateDataFlowFacts(output, symExpr);
        }
    }


    private void handleIntSext(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(0);
        var output = pcodeOp.getOutput();

        if (!intraCtx.isTracedVn(input)) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", input));
            return;
        }

        var inputFacts = intraCtx.getDataFlowFacts(input);
        for (var symExpr : inputFacts) {
            // TODO: IntSext need add constraint ?
            intraCtx.updateDataFlowFacts(output, symExpr);
        }
    }

    private void handleIntMult(PcodeOp pcodeOp) {
        var output = pcodeOp.getOutput();
        var input0 = pcodeOp.getInput(0);
        var input1 = pcodeOp.getInput(1);

        if (!intraCtx.isTracedVn(input0) && !intraCtx.isTracedVn(input1)) {
            Logging.debug("PCodeVisitor", String.format("both %s * %s is not traced", input0, input1));
            return;
        }

        // TODO: handle the case where input0 or input1 is not constant
        if (!input0.isConstant() && !input1.isConstant()) {
            Logging.warn("PCodeVisitor", String.format("%s * %s can not resolve", input0, input1));
            return;
        }

        KSet<SymbolExpr> inputFacts;
        long size = 0;
        if (input0.isConstant()) {
            inputFacts = intraCtx.getDataFlowFacts(input1);
            size = getSigned(input0);
        } else {
            inputFacts = intraCtx.getDataFlowFacts(input0);
            size = getSigned(input1);
        }

        if (OffsetSanityCheck(size)) {
            var sizeExpr = new SymbolExprManager.Builder().constant(size).build();
            for (var symExpr : inputFacts) {
                var newExpr = symExprManager.multiply(symExpr, sizeExpr);
                if (newExpr != null) {
                    intraCtx.updateDataFlowFacts(output, newExpr);
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

        if (!intraCtx.isTracedVn(input)) {
            Logging.debug("PCodeVisitor", "[PCode] Load addr is not interested: " + input);
            return;
        }

        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);
        var leftValueExprs = intraCtx.getDataFlowFacts(output);
        var loadAddrExprs = intraCtx.getDataFlowFacts(input);
        for (var loadAddrExpr : loadAddrExprs) {
            var loadedValueExpr = symExprManager.dereference(loadAddrExpr);

            interCtx.addFieldAccessExpr(loadedValueExpr, pcodeOp, outDT, AccessPoints.AccessType.LOAD);

            // If Loaded value is not null, means:
            // a = *(b), so set a and *(b) as type alias
            if (leftValueExprs != null) {
                Logging.debug("PCodeVisitor", "Loaded varnode has already held symbolExpr, set type alias ...");
                for (var leftValueExpr : leftValueExprs) {
                    interCtx.addTypeAliasRelation(loadedValueExpr, leftValueExpr, TypeAliasGraph.EdgeType.DATAFLOW);
                }
            }

            intraCtx.updateDataFlowFacts(output, loadedValueExpr);
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

        if (!intraCtx.isTracedVn(storedAddrVn)) {
            Logging.debug("PCodeVisitor", "Store address is not interested: " + storedAddrVn);
            return;
        }

        var rightValueExprs = intraCtx.getDataFlowFacts(rightValueVn);
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(pcodeOp.getInput(2));

        for (var storedAddrExpr : intraCtx.getDataFlowFacts(storedAddrVn)) {
            var storedValueExpr = symExprManager.dereference(storedAddrExpr);
            interCtx.addFieldAccessExpr(storedValueExpr, pcodeOp, storedValueDT, AccessPoints.AccessType.STORE);
            if (rightValueExprs != null) {
                for (var rightValueExpr : rightValueExprs) {
                    Logging.debug("PCodeVisitor", "Stored value has already held symbolExpr, set type alias ...");
                    interCtx.addTypeAliasRelation(rightValueExpr, storedValueExpr, TypeAliasGraph.EdgeType.DATAFLOW);
                }
            }
        }
    }

    private void handleINDCall(PcodeOp pcodeOp) {
        var indirectCallVn = pcodeOp.getInput(0);
        if (!intraCtx.isTracedVn(indirectCallVn)) {
            Logging.debug("PCodeVisitor", "[PCode] Indirect Call is not interested: " + indirectCallVn);
            return;
        }

        var indirectCallFacts = intraCtx.getDataFlowFacts(indirectCallVn);
        for (var symExpr : indirectCallFacts) {
            symExprManager.addExprAttribute(symExpr, SymbolExpr.Attribute.CODE_PTR);
        }
    }


    private void handleReturn(PcodeOp pcodeOp) {
        for (var retVn : pcodeOp.getInputs()) {
            if (!intraCtx.isTracedVn(retVn)) {
                Logging.debug("PCodeVisitor", "[PCode] Return value is not interested: " + retVn);
                continue;
            }

            var retFacts = intraCtx.getDataFlowFacts(retVn);
            for (var retExpr : retFacts) {
                intraCtx.setReturnExpr(retExpr);
                symExprManager.addExprAttribute(retExpr, SymbolExpr.Attribute.RETURN);
                Logging.info("PCodeVisitor", "[PCode] Setting Return Value: " + retExpr);
            }
        }
    }

    private void handleCall(PcodeOp pcodeOp) {
        var calleeAddr = pcodeOp.getInput(0).getAddress();
        var calleeNode = interCtx.callGraph.getNodebyAddr(calleeAddr);
        interCtx.getIntraContext(funcNode).addCallSite(pcodeOp, calleeNode);

        if (!interCtx.isFunctionSolved(calleeNode) && !calleeNode.isExternal) {
            Logging.warn("PCodeVisitor", "Callee function is not solved yet: " + calleeNode.value.getName());
            return;
        } else if (calleeNode.isTypeAgnostic) {
            Logging.info("PCodeVisitor", "Callee function: " + calleeNode.value.getName() + " is type agnostic, skip.");
            return;
        } else if (calleeNode.isExternal) {
            Logging.info("PCodeVisitor", "Callee function: " + calleeNode.value.getName() + " is an external function");
        } else {
            Logging.info("PCodeVisitor", "Callee function: " + calleeNode.value.getName() + " is solved");
        }

        // TODO: how to handle cases when arguments and parameters are inconsistency?
        for (int inputIdx = 1; inputIdx < pcodeOp.getNumInputs(); inputIdx++) {
            var argVn = pcodeOp.getInput(inputIdx);
            if (!intraCtx.isTracedVn(argVn)) {
                Logging.debug("PCodeVisitor", "Argument is not interested: " + argVn);
                continue;
            }

            var argFacts = intraCtx.getDataFlowFacts(argVn);
            for (var argExpr : argFacts) {
                symExprManager.addExprAttribute(argExpr, SymbolExpr.Attribute.ARGUMENT);

                if (!calleeNode.isExternal) {
                    var param = calleeNode.parameters.get(inputIdx - 1);
                    var paramExpr = new SymbolExprManager.Builder().rootSymbol(param).build();
                    interCtx.addTypeAliasRelation(argExpr, paramExpr, TypeAliasGraph.EdgeType.CALL);
                }
            }
        }

        if (calleeNode.isExternal) {
            handleExternalCall(pcodeOp, calleeNode);
            return;
        }

        // handle ReturnValue's receiver
        var receiverVn = pcodeOp.getOutput();
        if (receiverVn != null) {
            var retExprs = interCtx.intraCtxMap.get(calleeNode).getReturnExpr();
            if (retExprs.isEmpty()) {
                Logging.warn("PCodeVisitor", "Callee's Return Value is not set but Receiver exists.");
            } else {
                Logging.info("PCodeVisitor", "setting callsite receiver ...");
                var receiverFacts = intraCtx.getDataFlowFacts(receiverVn);
                if (receiverFacts != null) {
                    for (var receiverExpr : receiverFacts) {
                        for (var retValueExpr : retExprs) {
                            interCtx.addTypeAliasRelation(retValueExpr, receiverExpr, TypeAliasGraph.EdgeType.RETURN);
                        }
                    }
                }
                // If receiverFacts has no corresponding symbolExpr
                else {
                    for (var retValueExpr : retExprs) {
                        intraCtx.updateDataFlowFacts(receiverVn, retValueExpr);
                    }
                }
            }
        }
    }


    private void handleExternalCall(PcodeOp pcodeOp, FunctionNode calleeNode) {
        var externalFuncName = calleeNode.value.getName();
        Logging.info("PCodeVisitor", "External function call: " + externalFuncName);

        // TODO: handle memOp External function's wrapper
        // TODO: hold expr's constant value intra-procedural, which can be used to add constraints related to the memOp functions
        switch (externalFuncName) {
            case "memset" -> {
                var lengthArg = pcodeOp.getInput(3);
                if (lengthArg.isConstant()) {
                    var ptrExprs = intraCtx.getDataFlowFacts(pcodeOp.getInput(1));
                    for (var ptrExpr : ptrExprs) {
                        symExprManager.getOrCreateConstraint(ptrExpr).setTotalSize(lengthArg.getOffset());
                        Logging.info("PCodeVisitor", "memset: " + ptrExpr + " size: " + lengthArg.getOffset());
                    }
                }
            }

            case "memcpy" -> {
                var dstVn = pcodeOp.getInput(1);
                var srcVn = pcodeOp.getInput(2);
                var lengthVn = pcodeOp.getInput(3);
                if (!intraCtx.isTracedVn(dstVn) || !intraCtx.isTracedVn(srcVn)) {
                    return;
                }
                var dstExprs = intraCtx.getDataFlowFacts(dstVn);
                var srcExprs = intraCtx.getDataFlowFacts(srcVn);
                for (var dstExpr : dstExprs) {
                    for (var srcExpr : srcExprs) {
                        interCtx.addTypeAliasRelation(srcExpr, dstExpr, TypeAliasGraph.EdgeType.DATAFLOW);
                        Logging.info("PCodeVisitor", "memcpy: " + dstExpr + " <- " + srcExpr);
                        if (lengthVn.isConstant()) {
                            symExprManager.getOrCreateConstraint(dstExpr).setTotalSize(lengthVn.getOffset());
                            symExprManager.getOrCreateConstraint(srcExpr).setTotalSize(lengthVn.getOffset());
                            dstExpr.setVariableSize(lengthVn.getOffset());
                            dstExpr.setVariableSize(lengthVn.getOffset());
                            Logging.info("PCodeVisitor", "memcpy size: " + lengthVn.getOffset());
                        }
                    }
                }

            }
        }
    }


    private boolean checkIfHoldsCompositeType(SymbolExpr expr) {
        return expr.hasAttribute(SymbolExpr.Attribute.ARRAY) ||
                expr.hasAttribute(SymbolExpr.Attribute.STRUCT) ||
                expr.hasAttribute(SymbolExpr.Attribute.UNION);
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
