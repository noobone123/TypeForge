package blueprint.base.dataflow.context;

import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.SymbolExpr;
import blueprint.base.dataflow.constraints.ConstraintCollector;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.base.dataflow.types.TypeDescriptorFactory;
import blueprint.base.node.FunctionNode;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.HighSymbolHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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
    public Map<PcodeOp, FunctionNode> callsites;
    public ConstraintCollector collector;

    public IntraContext(FunctionNode funcNode, ConstraintCollector collector) {
        this.funcNode = funcNode;
        this.tracedSymbols = new HashSet<>();
        this.tracedVarnodes = new HashSet<>();
        this.dataFlowFacts = new HashMap<>();
        this.returnExprs = new HashSet<>();
        this.callsites = new HashMap<>();
        this.collector = collector;
    }

    public void setReturnExpr(SymbolExpr expr) {
        this.returnExprs.add(expr);
    }

    public Set<SymbolExpr> getReturnExpr() {
        return this.returnExprs;
    }

    public void addCallSite(PcodeOp op, FunctionNode funcNode) {
        callsites.put(op, funcNode);
    }

    public Map<PcodeOp, FunctionNode> getCallSites() {
        return callsites;
    }

    public void initialize() {
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
            var decompilerInferencedDT = symbol.getDataType();

            // Create the SymbolExpr and Constraint for the HighSymbol
            if (symbol.isGlobal()) {
                expr = new SymbolExpr.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(symbol), symbol).build();
                expr.addAttribute(SymbolExpr.Attribute.GLOBAL);
                constraint = collector.getConstraint(expr);
            } else {
                expr = new SymbolExpr.Builder().rootSymbol(symbol).build();
                constraint = collector.getConstraint(expr);
            }

            if (DataTypeHelper.isCompositeOrArray(decompilerInferencedDT)) {
                if (decompilerInferencedDT instanceof Array array) {
                    Logging.info("Context", "Found Array " + decompilerInferencedDT.getName());
                    expr.addAttribute(SymbolExpr.Attribute.ARRAY);
                    expr.setVariableSize(array.getLength());
                    constraint.addPolymorphicType(TypeDescriptorFactory.createArrayTypeDescriptor(array));
                }
                else if (decompilerInferencedDT instanceof Structure structure) {
                    Logging.info("Context", "Found Structure " + decompilerInferencedDT.getName());
                    expr.addAttribute(SymbolExpr.Attribute.STRUCT);
                    expr.setVariableSize(structure.getLength());
                    constraint.addPolymorphicType(TypeDescriptorFactory.createCompositeTypeDescriptor(structure));
                }
                else if (decompilerInferencedDT instanceof Union union) {
                    Logging.info("Context", "Found Union " + decompilerInferencedDT.getName());
                    expr.addAttribute(SymbolExpr.Attribute.UNION);
                    expr.setVariableSize(union.getLength());
                    constraint.addPolymorphicType(TypeDescriptorFactory.createCompositeTypeDescriptor(union));
                }
            } else if (decompilerInferencedDT instanceof Pointer ptr) {
                var ptrEE = ptr.getDataType();
                if (DataTypeHelper.isCompositeOrArray(ptrEE)) {
                    Logging.info("Context", "Found Pointer " + decompilerInferencedDT.getName());
                    expr.addAttribute(SymbolExpr.Attribute.POINTER_TO_COMPOSITE);
                    if (ptrEE instanceof Array array) {
                        constraint.addPolymorphicType(TypeDescriptorFactory.createArrayTypeDescriptor(array));
                    } else if (ptrEE instanceof Structure structure) {
                        constraint.addPolymorphicType(TypeDescriptorFactory.createCompositeTypeDescriptor(structure));
                    } else if (ptrEE instanceof Union union) {
                        constraint.addPolymorphicType(TypeDescriptorFactory.createCompositeTypeDescriptor(union));
                    }
                }
            } else {
                Logging.info("Context", "Found Primitive " + decompilerInferencedDT.getName());
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
        return dataFlowFacts.get(vn);
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