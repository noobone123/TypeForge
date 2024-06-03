package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.SymbolExpr;
import blueprint.base.dataflow.constraints.DummyType;
import blueprint.base.dataflow.constraints.PrimitiveTypeDescriptor;
import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.base.node.FunctionNode;
import blueprint.utils.DecompilerHelper;
import blueprint.utils.Global;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;

import java.util.*;

import static blueprint.utils.DecompilerHelper.getSigned;

public class PCodeVisitor {

    public Context ctx;
    public FunctionNode funcNode;

    /** The workList queue of current function */
    public LinkedList<PcodeOpAST> workList = new LinkedList<>();

    public PCodeVisitor(FunctionNode funcNode, Context ctx) {
        this.funcNode = funcNode;
        this.ctx = ctx;
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

        if (!ctx.isTracedVn(funcNode, inputs[0])) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[0]));
            return;
        }

        var inputFact_0 = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert inputFact_0 != null;

        if (inputs[1].isConstant()) {
            for (var symExpr: inputFact_0) {
                var delta = (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new SymbolExpr.Builder().constant(delta).build();
                    var newExpr = SymbolExpr.add(ctx, symExpr, deltaSym);
                    ctx.addNewSymbolExpr(funcNode, output, newExpr);
                    ctx.addTracedVarnode(funcNode, output);
                }
            }
        } else {
            if (!ctx.isTracedVn(funcNode, inputs[1])) {
                Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[1]));
                return;
            }
            var inputFact_1 = ctx.getIntraDataFlowFacts(funcNode, inputs[1]);
            for (var symExpr: inputFact_0) {
                for (var symExpr_1: inputFact_1) {
                    var newExpr = SymbolExpr.add(ctx, symExpr, symExpr_1);
                    ctx.addNewSymbolExpr(funcNode, output, newExpr);
                    ctx.addTracedVarnode(funcNode, output);
                }
            }
        }
    }


    private void handleAssign(PcodeOp pcodeOp) {
        var inputVn = pcodeOp.getInput(0);
        var outputVn = pcodeOp.getOutput();

        if (!ctx.isTracedVn(funcNode, inputVn)) {
            return;
        }

        var inputFact = ctx.getIntraDataFlowFacts(funcNode, inputVn);
        assert inputFact != null;

        ctx.addTracedVarnode(funcNode, outputVn);

        for (var inputSymExpr: inputFact) {
            // If output has already held symbolExpr, we can update the symbol alias map
            var outputFacts = ctx.getIntraDataFlowFacts(funcNode, outputVn);
            if (outputFacts != null) {
                for (var outputSymExpr: outputFacts) {
                    ctx.setTypeAlias(outputSymExpr, inputSymExpr);
                }
            }
            else {
                ctx.addNewSymbolExpr(funcNode, outputVn, inputSymExpr);
            }
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

        if (!ctx.isTracedVn(funcNode, inputs[0])) {
            Logging.debug("PCOdeVisitor", String.format("%s is not traced", inputs[0]));
            return;
        }

        var input0Fact = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert input0Fact != null;

        if (inputs[1].isConstant() && inputs[2].isConstant()) {
            for (var symExpr: input0Fact) {
                var delta = getSigned(inputs[1]) * getSigned(inputs[2]);
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new SymbolExpr.Builder().constant(delta).build();
                    var newExpr = SymbolExpr.add(ctx, symExpr, deltaSym);
                    ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), newExpr);
                }
            }

            ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());
        }
        // inputs[1] is index and inputs[2] is element size
        else if (!inputs[1].isConstant() && inputs[2].isConstant()) {
            if (!ctx.isTracedVn(funcNode, inputs[1])) {
                Logging.debug("PCodeVisitor", String.format("%s is not traced", inputs[1]));
                return;
            }
            var scaleValue = getSigned(inputs[2]);
            if (!OffsetSanityCheck(scaleValue)) {
                Logging.debug("PCodeVisitor", String.format("Scale value %d is not valid", scaleValue));
                return;
            }
            var scaleExpr = new SymbolExpr.Builder().constant(scaleValue).build();
            for (var symExpr: input0Fact) {
                var indexFacts = ctx.getIntraDataFlowFacts(funcNode, inputs[1]);
                for (var indexExpr: indexFacts) {
                    var newExpr = SymbolExpr.add(ctx, symExpr, SymbolExpr.multiply(ctx, indexExpr, scaleExpr));
                    ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), newExpr);
                }
                symExpr.addAttribute(SymbolExpr.Attribute.MAY_ARRAY_PTR);
            }

            ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());
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

        if (base.isRegister()) {
            var reg = Global.currentProgram.getRegister(base);
            // may be a reference of a local array or a stack structure or a stack array.
            // For Example:
            // 114_(unique, 0x3200, 8)[noHighSym], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16700_(const, 0xffffffffffffff58, 8)[local_a8]
            // 133_(unique, 0x3200, 8)[local_28], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16702_(const, 0xffffffffffffff58, 8)[local_a8]
            // 133_(unique, 0x3200, 8) and 114_(unique, 0x3200, 8) are actually the same symbol, but ghidra internal can not resolve it, so we manually recover it
            // 114_(unique, 0x3200, 8)[noHighSym] has no initial Facts but 133_(unique, 0x3200, 8)[local_28] has initial Facts
            if (reg.getName().equals("RSP")) {
                var sym = inputs[1].getHigh().getSymbol();
                if (sym != null) {
                    var expr = new SymbolExpr.Builder().rootSymbol(sym).build();
                    expr = SymbolExpr.reference(ctx, expr);
                    var outputFacts = ctx.getIntraDataFlowFacts(funcNode, pcodeOp.getOutput());

                    if (outputFacts == null) {
                        ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());
                        ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), expr);
                    } else {
                        for (var fact : outputFacts) {
                            ctx.setTypeAlias(fact, expr);
                        }
                    }
                }
            }
        }

        else if (base.isConstant()) {
            // In this case, Maybe an Address of a global variable
            if (base.getOffset() == 0 && inputs[1].isConstant()) {
                var globalSym = inputs[1].getHigh().getSymbol();
                if (globalSym != null && globalSym.isGlobal()) {
                    var globalSymExpr = new SymbolExpr.Builder().global(globalSym.getSymbol().getAddress(), globalSym).build();
                    var outputFacts = ctx.getIntraDataFlowFacts(funcNode, pcodeOp.getOutput());

                    if (outputFacts == null) {
                        ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());
                        ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), globalSymExpr);
                    } else {
                        for (var fact : outputFacts) {
                            ctx.setTypeAlias(fact, globalSymExpr);
                        }
                    }
                }
            }
        }

        else {
            Logging.warn("PCodeVisitor", String.format("%s is not a constant or register", base));
        }
    }


    private void handleMultiEqual(PcodeOp pcodeOp) {
        var output = pcodeOp.getOutput();
        var inputs = pcodeOp.getInputs();
        ctx.addTracedVarnode(funcNode, output);
        for (var input : inputs) {
            ctx.mergeSymbolExpr(funcNode, input, output, false);
        }
    }


    private void handleIntZext(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(0);
        var output = pcodeOp.getOutput();

        if (!ctx.isTracedVn(funcNode, input)) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", input));
            return;
        }

        ctx.addTracedVarnode(funcNode, output);
        var inputFacts = ctx.getIntraDataFlowFacts(funcNode, input);
        for (var symExpr : inputFacts) {
            // TODO: IntZext need add constraint ?
            ctx.addNewSymbolExpr(funcNode, output, symExpr);
        }
    }


    private void handleIntSext(PcodeOp pcodeOp) {
        var input = pcodeOp.getInput(0);
        var output = pcodeOp.getOutput();

        if (!ctx.isTracedVn(funcNode, input)) {
            Logging.debug("PCodeVisitor", String.format("%s is not traced", input));
            return;
        }

        ctx.addTracedVarnode(funcNode, output);
        var inputFacts = ctx.getIntraDataFlowFacts(funcNode, input);
        for (var symExpr : inputFacts) {
            // TODO: IntSext need add constraint ?
            ctx.addNewSymbolExpr(funcNode, output, symExpr);
        }
    }

    private void handleIntMult(PcodeOp pcodeOp) {
        var output = pcodeOp.getOutput();
        var input0 = pcodeOp.getInput(0);
        var input1 = pcodeOp.getInput(1);

        if (!ctx.isTracedVn(funcNode, input0) && !ctx.isTracedVn(funcNode, input1)) {
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
            inputFacts = ctx.getIntraDataFlowFacts(funcNode, input1);
            size = getSigned(input0);
        } else {
            inputFacts = ctx.getIntraDataFlowFacts(funcNode, input0);
            size = getSigned(input1);
        }

        if (OffsetSanityCheck(size)) {
            var sizeExpr = new SymbolExpr.Builder().constant(size).build();
            for (var symExpr : inputFacts) {
                var newExpr = SymbolExpr.multiply(ctx, symExpr, sizeExpr);
                ctx.addNewSymbolExpr(funcNode, output, newExpr);
            }
            ctx.addTracedVarnode(funcNode, output);
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

        if (!ctx.isTracedVn(funcNode, input)) {
            Logging.debug("PCodeVisitor", "[PCode] Load value is not interested: " + input);
            return;
        }

        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);

        ctx.addTracedVarnode(funcNode, output);

        var dataFlowFacts = ctx.getIntraDataFlowFacts(funcNode, input);
        for (var symExpr : dataFlowFacts) {
            var type = new PrimitiveTypeDescriptor(outDT);
            ctx.getAccessPoints().addMemAccessPoint(symExpr, pcodeOp, type, AccessPoints.AccessType.LOAD);

            var newExpr = SymbolExpr.dereference(ctx, symExpr);
            ctx.addNewSymbolExpr(funcNode, output, newExpr);
        }
    }

    /**
     * Same as handleLoad, but for STORE operation
     */
    private void handleStore(PcodeOp pcodeOp) {
        // the slot index of cur.varnode is 1, which means this varnode
        // represent the memory location to be stored
        var storedAddrVn = pcodeOp.getInput(1);
        var storedValueVn = pcodeOp.getInput(2);

        if (!ctx.isTracedVn(funcNode, storedAddrVn)) {
            Logging.debug("PCodeVisitor", "[PCode] Store address is not interested: " + storedAddrVn);
            return;
        }

        var storedValueFacts = ctx.getIntraDataFlowFacts(funcNode, storedValueVn);
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(pcodeOp.getInput(2));

        var storedTypes = new HashSet<TypeDescriptor>();
        if (storedValueFacts != null) {
            storedValueFacts.forEach(symExpr -> {
                if (symExpr.isGlobal()) {
                    storedTypes.add(new DummyType("CodePtr_or_DataPtr"));
                } else {
                    storedTypes.add(new PrimitiveTypeDescriptor(storedValueDT));
                }
            });
        } else {
            storedTypes.add(new PrimitiveTypeDescriptor(storedValueDT));
        }

        for (var symExpr : ctx.getIntraDataFlowFacts(funcNode, storedAddrVn)) {
            for (var type : storedTypes) {
                ctx.getAccessPoints().addMemAccessPoint(symExpr, pcodeOp, type, AccessPoints.AccessType.STORE);
            }
        }
    }


    private void handleReturn(PcodeOp pcodeOp) {
        for (var retVn : pcodeOp.getInputs()) {
            if (!ctx.isTracedVn(funcNode, retVn)) {
                Logging.debug("PCodeVisitor", "[PCode] Return value is not interested: " + retVn);
                continue;
            }

            var retFacts = ctx.getIntraDataFlowFacts(funcNode, retVn);
            for (var retExpr : retFacts) {
                ctx.intraCtxMap.get(funcNode).setReturnExpr(retExpr);
                ctx.getAccessPoints().addCallAccessPoint(retExpr, pcodeOp, AccessPoints.AccessType.RETURN_VALUE);
                Logging.info("PCodeVisitor", "[PCode] Setting Return Value: " + retExpr);
            }
        }
    }

    private void handleCall(PcodeOp pcodeOp) {
        var calleeAddr = pcodeOp.getInput(0).getAddress();
        var calleeNode = ctx.callGraph.getNodebyAddr(calleeAddr);

        if (!ctx.isFunctionSolved(calleeNode) && !calleeNode.isExternal) {
            Logging.warn("PCodeVisitor", "Callee function is not solved yet: " + calleeNode.value.getName());
            return;
        } else {
            Logging.info("PCodeVisitor", "Callee function: " + calleeNode.value.getName() + " is solved");
        }

        // TODO: how to handle cases when arguments and parameters are inconsistency?
        for (int inputIdx = 1; inputIdx < pcodeOp.getNumInputs(); inputIdx++) {
            var argVn = pcodeOp.getInput(inputIdx);
            if (!ctx.isTracedVn(funcNode, argVn)) {
                Logging.debug("PCodeVisitor", "Argument is not interested: " + argVn);
                continue;
            }

            var argFacts = ctx.getIntraDataFlowFacts(funcNode, argVn);
            for (var argExpr : argFacts) {
                argExpr.addAttribute(SymbolExpr.Attribute.ARGUMENT);
                ctx.getAccessPoints().addCallAccessPoint(argExpr, pcodeOp, AccessPoints.AccessType.ARGUMENT);

                if (!calleeNode.isExternal) {
                    var param = calleeNode.parameters.get(inputIdx - 1);
                    var paramExpr = new SymbolExpr.Builder().rootSymbol(param).build();
                    ctx.setTypeAlias(argExpr, paramExpr);
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
            var retExprs = ctx.intraCtxMap.get(calleeNode).getReturnExpr();
            if (retExprs.isEmpty()) {
                Logging.warn("PCodeVisitor", "Callee's Return Value is not set but Receiver exists.");
            } else {
                Logging.info("PCodeVisitor", "setting callsite receiver ...");
                var receiverFacts = ctx.getIntraDataFlowFacts(funcNode, receiverVn);
                if (receiverFacts != null) {
                    for (var receiverExpr : receiverFacts) {
                        for (var retValueExpr : retExprs) {
                            ctx.setTypeAlias(receiverExpr, retValueExpr);
                        }
                    }
                }
                // If receiverFacts has no corresponding symbolExpr
                else {
                    for (var retValueExpr : retExprs) {
                        ctx.addNewSymbolExpr(funcNode, receiverVn, retValueExpr);
                    }
                    ctx.addTracedVarnode(funcNode, receiverVn);
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
                    var ptrExprs = ctx.getIntraDataFlowFacts(funcNode, pcodeOp.getInput(1));
                    for (var ptrExpr : ptrExprs) {
                        ptrExpr.setVariableSize(lengthArg.getOffset());
                        ctx.getConstraint(ptrExpr).setTotalSize(lengthArg.getOffset());
                        Logging.info("PCodeVisitor", "memset: " + ptrExpr + " size: " + lengthArg.getOffset());
                    }
                }
            }

            case "memcpy" -> {
                var dstVn = pcodeOp.getInput(1);
                var srcVn = pcodeOp.getInput(2);
                var lengthVn = pcodeOp.getInput(3);
                if (!ctx.isTracedVn(funcNode, dstVn) || !ctx.isTracedVn(funcNode, srcVn)) {
                    return;
                }
                var dstExprs = ctx.getIntraDataFlowFacts(funcNode, dstVn);
                var srcExprs = ctx.getIntraDataFlowFacts(funcNode, srcVn);
                for (var dstExpr : dstExprs) {
                    for (var srcExpr : srcExprs) {
                        ctx.setTypeAlias(dstExpr, srcExpr);
                        Logging.info("PCodeVisitor", "memcpy: " + dstExpr + " <- " + srcExpr);
                        if (lengthVn.isConstant()) {
                            ctx.getConstraint(dstExpr).setTotalSize(lengthVn.getOffset());
                            ctx.getConstraint(srcExpr).setTotalSize(lengthVn.getOffset());
                            dstExpr.setVariableSize(lengthVn.getOffset());
                            dstExpr.setVariableSize(lengthVn.getOffset());
                            Logging.info("PCodeVisitor", "memcpy size: " + lengthVn.getOffset());
                        }
                    }
                }

            }
        }
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
