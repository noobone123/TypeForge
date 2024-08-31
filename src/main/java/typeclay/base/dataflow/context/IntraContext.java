package typeclay.base.dataflow.context;

import typeclay.base.dataflow.KSet;
import typeclay.base.dataflow.SymbolExpr.SymbolExpr;
import typeclay.base.dataflow.SymbolExpr.SymbolExprManager;
import typeclay.base.dataflow.skeleton.TypeConstraint;
import typeclay.base.dataflow.types.TypeDescriptorManager;
import typeclay.base.node.FunctionNode;
import typeclay.utils.DataTypeHelper;
import typeclay.utils.HighSymbolHelper;
import typeclay.utils.Logging;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class IntraContext {
    public FunctionNode funcNode;

    /** The candidate HighSymbols that need to collect data-flow facts */
    public final HashSet<HighSymbol> tracedSymbols;
    public final HashSet<Varnode> tracedVarnodes;

    /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
    public HashMap<Varnode, KSet<SymbolExpr>> dataFlowFacts;
    public HashSet<SymbolExpr> returnExprs;
    public int dataFlowFactKSize = 10;
    public SymbolExprManager symbolExprManager;

    public IntraContext(FunctionNode funcNode, SymbolExprManager symbolExprManager) {
        this.funcNode = funcNode;
        this.tracedSymbols = new HashSet<>();
        this.tracedVarnodes = new HashSet<>();
        this.dataFlowFacts = new HashMap<>();
        this.returnExprs = new HashSet<>();
        this.symbolExprManager = symbolExprManager;
    }

    public void setReturnExpr(SymbolExpr expr) {
        this.returnExprs.add(expr);
        expr.isReturnVal = true;
    }

    public Set<SymbolExpr> getReturnExpr() {
        return this.returnExprs;
    }

    public boolean initialize() {
        // initialize current function
        if (!funcNode.initCheck()) { return false; }

        /*
         * IMPORTANT: Update the candidate HighSymbols that need to collect data-flow facts
         * Currently, we only collect data-flow facts on :
         * 1. parameters
         * 2. arguments
         * 3. return values
         * and their aliases.
         */
        if (funcNode.parameters.isEmpty()) {
            Logging.warn("IntraSolver", "No parameters in the function");
        }
        for (var symbol : funcNode.parameters) {
            addTracedSymbol(symbol);
        }
        for (var symbol : funcNode.localVariables) {
            addTracedSymbol(symbol);
        }
        for (var symbol : funcNode.globalVariables) {
            addTracedSymbol(symbol);
        }

        // initialize the data-flow facts
        initDataFlowFacts();
        return true;
    }


    public void addTracedSymbol(HighSymbol highSymbol) {
        tracedSymbols.add(highSymbol);
        Logging.info("IntraContext", "Add traced symbol: " + highSymbol.getName());
    }

    public void addTracedVarnode(Varnode vn) {
        tracedVarnodes.add(vn);
        Logging.debug("IntraContext", "Add traced varnode: " + vn.toString());
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initDataFlowFacts() {
        for (var symbol: tracedSymbols) {
            Logging.info("IntraContext", "Candidate HighSymbol: " + symbol.getName());

            SymbolExpr expr;
            TypeConstraint constraint;
            DataType dt;

            // Create the SymbolExpr and Constraint for the HighSymbol
            if (symbol.isGlobal()) {
                expr = new SymbolExprManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(symbol), symbol).build();
                symbolExprManager.addExprAttribute(expr, SymbolExpr.Attribute.GLOBAL);
                dt = symbol.getDataType();
            } else {
                expr = new SymbolExprManager.Builder().rootSymbol(symbol).build();
                dt = funcNode.getDecompilerInferredDT(symbol.getStorage());
                if (dt == null) {
                    dt = symbol.getDataType();
                }

                if (funcNode.parameters.contains(symbol)) {
                    expr.isParameter = true;
                }
            }
            symbolExprManager.addDecompilerInferredType(expr, dt);
            constraint = symbolExprManager.createConstraint(expr);

            if (DataTypeHelper.isCompositeOrArray(dt)) {
                if (dt instanceof Array array) {
                    Logging.info("IntraContext", "Found Array " + dt.getName());
                    symbolExprManager.addExprAttribute(expr, SymbolExpr.Attribute.ARRAY);
                    expr.setVariableSize(array.getLength());
                    constraint.addPolymorphicType(TypeDescriptorManager.createArrayTypeDescriptor(array));
                }
                else if (dt instanceof Structure structure) {
                    Logging.info("IntraContext", "Found Structure " + dt.getName());
                    symbolExprManager.addExprAttribute(expr, SymbolExpr.Attribute.STRUCT);
                    expr.setVariableSize(structure.getLength());
                    constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(structure));
                }
                else if (dt instanceof Union union) {
                    Logging.info("IntraContext", "Found Union " + dt.getName());
                    symbolExprManager.addExprAttribute(expr, SymbolExpr.Attribute.UNION);
                    expr.setVariableSize(union.getLength());
                    constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(union));
                }
            } else if (dt instanceof Pointer ptrDT) {
                if (DataTypeHelper.isPointerToCompositeDataType(ptrDT)) {
                    Logging.info("IntraContext", "Found Pointer " + ptrDT.getName());
                    symbolExprManager.addExprAttribute(expr, SymbolExpr.Attribute.POINTER_TO_COMPOSITE);
                    if (ptrDT.getDataType() instanceof Array array) {
                        constraint.addPolymorphicType(TypeDescriptorManager.createArrayTypeDescriptor(array));
                    } else if (ptrDT.getDataType() instanceof Structure structure) {
                        constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(structure));
                    } else if (ptrDT.getDataType() instanceof Union union) {
                        constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(union));
                    }
                }
            } else {
                Logging.info("IntraContext", "Found Primitive " + dt.getName());
            }

            // In some time, a HighSymbol may not have corresponding HighVariable due to some reasons:
            // 1. HighSymbol is not used in the function
            // 2. HighSymbol is used in the function, but ghidra's decompiler failed to find the HighVariable
            if (symbol.getHighVariable() == null) {
                Logging.warn("IntraContext", funcNode.value.getName() + " -> HighSymbol: " + symbol.getName() + " has no HighVariable");
            } else {
                // Initialize the dataFlowFacts using the interested varnodes and add
                // all varnode instances of the HighVariable to the IntraContext's tracedVarnodes
                // TODO: this may cause flow-insensitive, ... we can improve it in the future
                for (var vn: symbol.getHighVariable().getInstances()) {
                    addTracedVarnode(vn);
                    updateDataFlowFacts(vn, expr);
                }
            }
        }
    }

    /**
     * create a new SymbolExpr and add it to the dataFlowFacts
     * @param vn the varnode which holds the dataflow fact
     * @param symbolExpr the new symbolExpr
     */
    public void updateDataFlowFacts(Varnode vn, SymbolExpr symbolExpr) {
        var curDataFlowFact = dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(dataFlowFactKSize));
        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("IntraContext", "New " + vn + " -> " + curDataFlowFact);
        }
        addTracedVarnode(vn);
    }

    public KSet<SymbolExpr> getDataFlowFacts(Varnode vn) {
        if (dataFlowFacts.get(vn) == null) {
            return new KSet<>(dataFlowFactKSize);
        } else {
            return dataFlowFacts.get(vn);
        }
    }

    public boolean isTracedVn(Varnode vn) {
        return tracedVarnodes.contains(vn);
    }

    /**
     * Merge the dataflow facts from input to output
     * @param input the input varnode
     * @param output the output varnode
     * @param isStrongUpdate if true, the output varnode's dataflow facts will be cleared before merging
     */
    public void mergeDataFlowFacts(Varnode input, Varnode output, boolean isStrongUpdate) {
        var inputFacts = dataFlowFacts.get(input);

        if (inputFacts == null) {
            Logging.warn("Context", "Failed to get dataflow fact for " + input);
            return;
        }

        var outputFacts = dataFlowFacts.computeIfAbsent(output, k -> new KSet<>(dataFlowFactKSize));
        if (isStrongUpdate) {
            outputFacts.clear();
        }

        outputFacts.merge(inputFacts);
        addTracedVarnode(output);
        Logging.debug("IntraContext", "Merge " + output + " -> " + outputFacts);
    }
}