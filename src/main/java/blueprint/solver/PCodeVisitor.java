package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.SymbolExpr;
import blueprint.base.dataflow.constraints.DummyType;
import blueprint.base.dataflow.constraints.PrimitiveTypeDescriptor;
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
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleAddOrSub(pcode);
                }
                case PcodeOp.COPY, PcodeOp.CAST -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleAssign(pcode);
                }
                case PcodeOp.PTRADD -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handlePtrAdd(pcode);
                }
                case PcodeOp.PTRSUB -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handlePtrSub(pcode);
                }
                case PcodeOp.MULTIEQUAL -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleMultiEqual(pcode);
                }
                case PcodeOp.INT_ZEXT -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleIntZext(pcode);
                }
                case PcodeOp.INT_SEXT -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleIntSext(pcode);
                }
                case PcodeOp.INT_MULT -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleIntMult(pcode);
                }
                case PcodeOp.LOAD -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleLoad(pcode);
                }
                case PcodeOp.STORE -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleStore(pcode);
                }
                case PcodeOp.CALL -> {
                    Logging.debug("[PCode] " + getPCodeRepresentation(pcode));
                    handleCall(pcode);
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

        ctx.addTracedVarnode(funcNode, output);
        var inputFact_0 = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert inputFact_0 != null;


        if (inputs[1].isConstant()) {
            for (var symExpr: inputFact_0) {
                var delta = (pcodeOp.getOpcode() == PcodeOp.INT_ADD ? getSigned(inputs[1]) : -getSigned(inputs[1]));
                if (OffsetSanityCheck(delta)) {
                    var deltaSym = new SymbolExpr.Builder().constant(delta).build();
                    var newExpr = add(symExpr, deltaSym);
                    ctx.addNewSymbolExpr(funcNode, output, newExpr);
                }
            }
        } else {
            var inputFact_1 = ctx.getIntraDataFlowFacts(funcNode, inputs[1]);
            for (var symExpr: inputFact_0) {
                for (var symExpr_1: inputFact_1) {
                    var newExpr = add(symExpr, symExpr_1);
                    ctx.addNewSymbolExpr(funcNode, output, newExpr);
                }
            }
        }
    }


    private void handleAssign(PcodeOp pcodeOp) {
        var inputVn = pcodeOp.getInput(0);
        var outputVn = pcodeOp.getOutput();

        if (!ctx.isInterestedVn(funcNode, inputVn)) {
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
        // TODO: handle the case where input1 or input2 is not constant
        if (!inputs[1].isConstant() || !inputs[2].isConstant()) {
            return;
        }

        var inputFact = ctx.getIntraDataFlowFacts(funcNode, inputs[0]);
        assert inputFact != null;

        ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());

        for (var symExpr: inputFact) {
            var delta = getSigned(inputs[1]) * getSigned(inputs[2]);
            if (OffsetSanityCheck(delta)) {
                var deltaSym = new SymbolExpr.Builder().constant(delta).build();
                var newExpr = add(symExpr, deltaSym);
                ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), newExpr);
            }
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
            // may be a reference of a local variable
            if (reg.getName().equals("RSP")) {
                var refSym = inputs[1].getHigh().getSymbol();
                if (refSym != null) {
                    var refSymExpr = reference(new SymbolExpr.Builder().rootSymbol(refSym).build());
                    var outputFacts = ctx.getIntraDataFlowFacts(funcNode, pcodeOp.getOutput());
                    // For Example:
                    // 114_(unique, 0x3200, 8)[noHighSym], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16700_(const, 0xffffffffffffff58, 8)[local_a8]
                    // 133_(unique, 0x3200, 8)[local_28], PTRSUB, 10973_(register, 0x20, 8)[noHighSym], 16702_(const, 0xffffffffffffff58, 8)[local_a8]
                    // 133_(unique, 0x3200, 8) and 114_(unique, 0x3200, 8) are actually the same symbol, but ghidra internal can not resolve it, so we manually recover it
                    // 114_(unique, 0x3200, 8)[noHighSym] has no initial Facts but 133_(unique, 0x3200, 8)[local_28] has initial Facts
                    if (outputFacts == null) {
                        ctx.addTracedVarnode(funcNode, pcodeOp.getOutput());
                        ctx.addNewSymbolExpr(funcNode, pcodeOp.getOutput(), refSymExpr);
                    } else {
                        for (var fact : outputFacts) {
                            ctx.setTypeAlias(fact, refSymExpr);
                        }
                    }
                }
            }
        }

        else if (base.isConstant()) {
            // In this case, Maybe an Address of a global variable
            if (base.getOffset() == 0 && inputs[1].isConstant()) {
                var globalSym = inputs[1].getHigh().getSymbol();
                if (globalSym != null) {
                    var globalSymExpr = new SymbolExpr.Builder().rootSymbol(globalSym).build();
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
            Logging.warn("[PCode] PTRSUB: " + base + " is not a constant or register");
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

        if (!ctx.isInterestedVn(funcNode, input)) {
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

        if (!ctx.isInterestedVn(funcNode, input)) {
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

        if (!ctx.isInterestedVn(funcNode, input0) && !ctx.isInterestedVn(funcNode, input1)) {
            return;
        }

        // TODO: handle the case where input0 or input1 is not constant
        if (!input0.isConstant() && !input1.isConstant()) {
            Logging.warn(String.format("[PCode] INT_MULT: %s * %s can not resolve", input0, input1));
            return;
        }

        KSet<SymbolExpr> inputFacts;
        long size = 0;
        if (input0.isConstant()) {
            inputFacts = ctx.getIntraDataFlowFacts(funcNode, input1);
            size = input0.getOffset();
        } else {
            inputFacts = ctx.getIntraDataFlowFacts(funcNode, input0);
            size = input1.getOffset();
        }

        var sizeExpr = new SymbolExpr.Builder().constant(size).build();
        for (var symExpr : inputFacts) {
            var newExpr = new SymbolExpr.Builder().index(symExpr).scale(sizeExpr).build();
            ctx.addNewSymbolExpr(funcNode, output, newExpr);
        }
    }


    private void handleCall(PcodeOp pcodeOp) {
        var calleeAddr = pcodeOp.getInput(0).getAddress();
        var calleeNode = ctx.callGraph.getNodebyAddr(calleeAddr);
        var returnVn = pcodeOp.getOutput();
        if (returnVn != null) {
            Logging.info("[PCode] Return value: " + returnVn);
        }

        if (calleeNode.isExternal) {
            handleExternalCall(pcodeOp, calleeNode);
            return;
        }

        if (!ctx.isFunctionSolved(calleeNode)) {
            Logging.warn("Callee function is not solved yet: " + calleeNode.value.getName());
            return;
        }
        Logging.info("Callee function: " + calleeNode.value.getName() + " is solved");

        // TODO: how to handle cases when arguments and parameters are inconsistency?
        for (int inputIdx = 1; inputIdx < pcodeOp.getNumInputs(); inputIdx++) {
            var argVn = pcodeOp.getInput(inputIdx);
            if (!ctx.isInterestedVn(funcNode, argVn)) {
                Logging.warn("[PCode] Argument is not interested: " + argVn);
                continue;
            }

            var argFacts = ctx.getIntraDataFlowFacts(funcNode, argVn);
            for (var symExpr : argFacts) {
                // If the argument is not a simple expression, we need to add it as an access point
                if (!symExpr.isRootSymExpr() && !symExpr.isNoZeroConst()) {
                    ctx.addAccessPoint(symExpr, pcodeOp, new DummyType(), AccessPoints.AccessType.ARGUMENT);
                }

                var param = calleeNode.parameters.get(inputIdx - 1);
                var paramExpr = new SymbolExpr.Builder().rootSymbol(param).build();
                ctx.setTypeAlias(symExpr, paramExpr);
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

        // The amount of data loaded by this instruction is determined by the size of the output variable
        DataType outDT = DecompilerHelper.getDataTypeTraceForward(output);

        ctx.addTracedVarnode(funcNode, output);

        var dataFlowFacts = ctx.getIntraDataFlowFacts(funcNode, input);
        for (var symExpr : dataFlowFacts) {
            var type = new PrimitiveTypeDescriptor(outDT);
            ctx.addAccessPoint(symExpr, pcodeOp, type, AccessPoints.AccessType.LOAD);

            var newExpr = dereference(symExpr);
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
        var storedValueDT = DecompilerHelper.getDataTypeTraceBackward(pcodeOp.getInput(2));

        for (var symExpr : ctx.getIntraDataFlowFacts(funcNode, storedAddrVn)) {
            var type = new PrimitiveTypeDescriptor(storedValueDT);
            ctx.addAccessPoint(symExpr, pcodeOp, type, AccessPoints.AccessType.STORE);
        }
    }

    private void handleExternalCall(PcodeOp pcodeOp, FunctionNode calleeNode) {
        var externalFuncName = calleeNode.value.getName();
        Logging.info("External function call: " + externalFuncName);

        switch (externalFuncName) {
            case "memset" -> {
                var lengthArg = pcodeOp.getInput(3);
                if (lengthArg.isConstant()) {
                    var symExprs = ctx.getIntraDataFlowFacts(funcNode, pcodeOp.getInput(1));
                    for (var symExpr : symExprs) {
                        if (!symExpr.hasOffset()) {
                            // var constraint = ctx.symToConstraints.computeIfAbsent(symExpr.getBaseSymbol(), k -> new ComplexTypeConstraint());
                            Logging.info("memset: " + symExpr);
                            // constraint.setSize(lengthArg.getOffset());
                        }

                        // If the argument is not a simple expression, we need to add it as an access point
                        if (!symExpr.isRootSymExpr() && !symExpr.isNoZeroConst()) {
                            ctx.addAccessPoint(symExpr, pcodeOp, null, AccessPoints.AccessType.ARGUMENT);
                        }
                    }
                }
            }

            case "memcpy" -> {
                var dstVn = pcodeOp.getInput(1);
                var srcVn = pcodeOp.getInput(2);
                var lengthVn = pcodeOp.getInput(3);
                Logging.info("memcpy: " + srcVn + " -> " + dstVn + " length: " + lengthVn);
            }
        }
    }


    public SymbolExpr add(SymbolExpr a, SymbolExpr b) {
        if (a.hasIndexScale() && b.hasIndexScale()) {
            Logging.error(String.format("[SymbolExpr] Unsupported add operation: %s + %s", a.getRepresentation(), b.getRepresentation()));
        }

        // ensure that the constant value is always on the right side of the expression
        if (a.isNoZeroConst() && !b.isNoZeroConst()) {
            return add(b, a);
        }
        // ensure that the index * scale is always on the right side of base
        if (a.hasIndexScale() && !a.hasBase()) {
            if (!b.isConst()) {
                return add(b, a);
            }
        }

        SymbolExpr.Builder builder = new SymbolExpr.Builder();
        if (a.isConst() && b.isConst()) {
            builder.constant(a.constant + b.constant);
        }
        else if (a.isRootSymExpr() || a.isDereference()) {
            if (b.hasIndexScale()) {
                // Set `base + index * scale` and `base` type alias
                ctx.setTypeAlias(a, new SymbolExpr.Builder().base(a).index(b.indexExpr).scale(b.scaleExpr).build());
                builder.base(a).index(b.indexExpr).scale(b.scaleExpr).offset(b.offsetExpr);
            } else {
                builder.base(a).offset(b);
            }
        }
        else if (!a.hasBase() && a.hasIndexScale()) {
            if (a.hasOffset()) {
                builder.index(a.indexExpr).scale(a.scaleExpr).offset(add(a.offsetExpr, b));
            } else {
                builder.index(a.indexExpr).scale(a.scaleExpr).offset(b);
            }
        }

        else if (a.hasBase() && a.hasOffset() && !a.hasIndexScale()) {
            builder.base(a.baseExpr).offset(add(a.offsetExpr, b));
        }
        else if (a.hasBase() && a.hasIndexScale()) {
            if (a.hasOffset()) {
                builder.base(a.baseExpr).index(a.indexExpr).scale(a.scaleExpr).offset(add(a.offsetExpr, b));
            } else {
                builder.base(a.baseExpr).index(a.indexExpr).scale(a.scaleExpr).offset(b);
            }
        }
        else {
            Logging.error(String.format("[SymbolExpr] Unsupported add operation: %s + %s", a.getRepresentation(), b.getRepresentation()));
        }

        return builder.build();
    }

    // TODO: add Type alias, if nestedExpr is TypeAlias, then the dereference should also be TypeAlias
    public SymbolExpr dereference(SymbolExpr a) {
        if (a.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot dereference a constant value.");
        }
        return new SymbolExpr.Builder().dereference(a).build();
    }

    public SymbolExpr reference(SymbolExpr a) {
        if (a.isNoZeroConst()) {
            throw new IllegalArgumentException("Cannot reference a constant value.");
        }
        return new SymbolExpr.Builder().reference(a).build();
    }


    /**
     * Check if the offset is sane to be a structure offset
     * @param offset the offset
     * @return true if the offset is sane
     */
    private boolean OffsetSanityCheck(long offset) {
        if (offset < 0) {
            return false;
        }
        // TODO: 0x2000 is a reasonable limit for a structure ?
        else return offset <= 0x2000;
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
