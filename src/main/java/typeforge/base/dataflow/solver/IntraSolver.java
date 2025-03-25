package typeforge.base.dataflow.solver;

import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import typeforge.analyzer.PCodeVisitor;
import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.KSet;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
import typeforge.base.dataflow.types.TypeDescriptorManager;
import typeforge.base.node.CallSite;
import typeforge.base.node.FunctionNode;
import typeforge.utils.DataTypeHelper;
import typeforge.utils.HighSymbolHelper;
import typeforge.utils.Logging;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.Varnode;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class IntraSolver {
    public FunctionNode funcNode;

    private final PCodeVisitor visitor;

    public TFGManager graphManager;
    public NMAEManager exprManager;
    public AccessPoints APs;

    /** The candidate HighSymbols that need to collect data-flow facts */
    public final HashSet<HighSymbol> tracedSymbols;
    public final HashSet<Varnode> tracedVarnodes;

    /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
    public HashMap<Varnode, KSet<NMAE>> dataFlowFacts;
    public HashSet<NMAE> returnExprs;
    public int dataFlowFactKSize = 10;

    /** The bridge information used for connecting TFG between functions in inter-solver */
    public Map<CallSite, Map<Varnode, KSet<NMAE>>> bridgeInfo;

    public IntraSolver(FunctionNode funcNode, NMAEManager exprManager,
                       TFGManager graphManager, AccessPoints APs) {
        this.funcNode = funcNode;
        this.tracedSymbols = new HashSet<>();
        this.tracedVarnodes = new HashSet<>();
        this.dataFlowFacts = new HashMap<>();
        this.returnExprs = new HashSet<>();

        // Following Components are derived from InterSolver
        this.exprManager = exprManager;
        this.graphManager = graphManager;
        this.APs = APs;

        this.bridgeInfo = new HashMap<>();

        this.visitor = new PCodeVisitor(this.funcNode, this, true);
    }

    public void solve() {
        Logging.info("IntraSolver", "Solving function: " + funcNode.value.getName());

        if (!initialize()) {
            Logging.warn("IntraSolver", "Failed to initialize intraContext: " + funcNode.value.getName());
            return;
        }
        visitor.prepare();
        visitor.run();

        Logging.info("IntraSolver", "Solved function: " + funcNode.value.getName());
    }

    public void setReturnExpr(NMAE expr) {
        this.returnExprs.add(expr);
        expr.isReturnVal = true;
    }

    public Set<NMAE> getReturnExpr() {
        return this.returnExprs;
    }

    public boolean initialize() {
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
        Logging.debug("IntraSolver", "Add traced symbol: " + highSymbol.getName());
    }

    public void addTracedVarnode(Varnode vn) {
        tracedVarnodes.add(vn);
        Logging.debug("IntraSolver", "Add traced varnode: " + vn.toString());
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initDataFlowFacts() {
        for (var symbol: tracedSymbols) {
            Logging.debug("IntraSolver", "Candidate HighSymbol: " + symbol.getName());

            NMAE expr;
            TypeConstraint constraint;
            DataType dt;

            // Create the SymbolExpr and Constraint for the HighSymbol
            if (symbol.isGlobal()) {
                expr = new NMAEManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(symbol), symbol).build();
                exprManager.addExprAttribute(expr, NMAE.Attribute.GLOBAL);
                dt = symbol.getDataType();
            } else {
                expr = new NMAEManager.Builder().rootSymbol(symbol).build();
                dt = funcNode.getDecompilerInferredDT(symbol.getStorage());
                if (dt == null) {
                    dt = symbol.getDataType();
                }

                if (funcNode.parameters.contains(symbol)) {
                    expr.isParameter = true;
                }
            }
            exprManager.addDecompilerInferredType(expr, dt);
            // TODO: how to represent these stack allocated HighSymbol,
            //  as they always have no corresponding HighVariable and Varnodes.
            //  Maybe reference to them? like. &varname[Composite]
            constraint = exprManager.createConstraint(expr);

            if (DataTypeHelper.isCompositeOrArray(dt)) {
                if (dt instanceof Array array) {
                    Logging.info("IntraSolver", String.format("Found Array: %s -> %s", expr.toString(), dt.getName()));
                    exprManager.addExprAttribute(expr, NMAE.Attribute.ARRAY);
                    // expr.setVariableSize(array.getLength());
                    constraint.addPolymorphicType(TypeDescriptorManager.createArrayTypeDescriptor(array));
                }
                else if (dt instanceof Structure structure) {
                    Logging.info("IntraSolver", String.format("Found Structure: %s -> %s", expr.toString(), dt.getName()));
                    exprManager.addExprAttribute(expr, NMAE.Attribute.STRUCT);
                    // expr.setVariableSize(structure.getLength());
                    constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(structure));
                }
                else if (dt instanceof Union union) {
                    Logging.info("IntraSolver", String.format("Found Union: %s -> %s", expr.toString(), dt.getName()));
                    exprManager.addExprAttribute(expr, NMAE.Attribute.UNION);
                    // expr.setVariableSize(union.getLength());
                    constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(union));
                }
            } else if (dt instanceof Pointer ptrDT) {
                if (DataTypeHelper.isPointerToCompositeDataType(ptrDT)) {
                    Logging.info("IntraSolver", String.format("Found Pointer to Composite: %s -> %s", expr.toString(), dt.getName()));
                    exprManager.addExprAttribute(expr, NMAE.Attribute.POINTER_TO_COMPOSITE);
                    if (ptrDT.getDataType() instanceof Structure structure) {
                        constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(structure));
                    } else if (ptrDT.getDataType() instanceof Union union) {
                        constraint.addPolymorphicType(TypeDescriptorManager.createCompositeTypeDescriptor(union));
                    }
                }
            } else {
                Logging.debug("IntraSolver", String.format("Found Primitive: %s -> %s", expr.toString(), dt.getName()));
            }

            // In some time, a HighSymbol may not have corresponding HighVariable due to some reasons:
            // 1. HighSymbol is not used in the function
            // 2. Global Variable
            // 3. Stack Array or Structure
            // (PS: Stack Array or Structure are actually traced represented as `&varname[Composite]` in the PCodeVisitor)
            if (symbol.getHighVariable() == null) {
                Logging.warn("IntraSolver", funcNode.value.getName() + " -> HighSymbol: " + symbol.getName() + " has no HighVariable");
            } else {
                // Initialize the dataFlowFacts using the interested varnodes and add
                // all varnode instances of the HighVariable to the IntraContext's tracedVarnodes
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
    public void updateDataFlowFacts(Varnode vn, NMAE symbolExpr) {
        var curDataFlowFact = dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(dataFlowFactKSize));
        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("IntraSolver", "New " + vn + " -> " + curDataFlowFact);
        }
        addTracedVarnode(vn);
    }

    public KSet<NMAE> getDataFlowFacts(Varnode vn) {
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
            Logging.warn("IntraSolver", "Failed to get dataflow fact for " + input);
            return;
        }

        var outputFacts = dataFlowFacts.computeIfAbsent(output, k -> new KSet<>(dataFlowFactKSize));
        if (isStrongUpdate) {
            outputFacts.clear();
        }

        outputFacts.merge(inputFacts);
        addTracedVarnode(output);
        Logging.debug("IntraSolver", "Merge " + output + " -> " + outputFacts);
    }

    /**
     * Add a field access expression (NMAE) into NMAEManager and AccessPoints
     * @param expr the field access expression
     * @param pcodeOp the pcodeOp that generates the field access expression
     * @param dt the primtive type of the field access expression
     * @param accessType LOAD or STORE
     * @param function the function that contains the field access expression
     */
    public void addFieldAccessExpr(NMAE expr, PcodeOp pcodeOp, DataType dt, AccessPoints.AccessType accessType, Function function) {
        exprManager.addFieldExpr(expr);
        APs.addFieldAccessPoint(expr, pcodeOp, dt, accessType, function);
    }

    /**
     * Add edges in the Type Flow Graph
     * @param from the source NMAE
     * @param to the target NMAE
     * @param edgeType the type of the edge
     */
    public void addTFGEdges(NMAE from, NMAE to, TypeFlowGraph.EdgeType edgeType) {
        if (from.equals(to)) {
            return;
        }

        if (isMergedVariableExpr(from) || isMergedVariableExpr(to)) {
            Logging.info("IntraSolver",
                    String.format("Skip adding TFG Edges between merged variables: %s and %s", from, to));
            return;
        }

        graphManager.addEdge(from, to, edgeType);
    }


    private boolean isMergedVariableExpr(NMAE expr) {
        if (expr.isConst) { return false; }
        if (expr.isTemp) { return false; }
        var rootSym = expr.getRootHighSymbol();
        if (rootSym.isGlobal()) { return false; }
        if (funcNode.mergedVariables.isEmpty()) { return false; }
        else {
            return funcNode.mergedVariables.contains(rootSym);
        }
    }
}