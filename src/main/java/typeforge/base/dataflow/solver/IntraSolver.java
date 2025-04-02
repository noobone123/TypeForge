package typeforge.base.dataflow.solver;

import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import typeforge.base.dataflow.AccessPoints;
import typeforge.base.dataflow.KSet;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.Skeleton;
import typeforge.base.dataflow.TFG.TFGManager;
import typeforge.base.dataflow.TFG.TypeFlowGraph;
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
        Logging.debug("IntraSolver", "Solving function: " + funcNode.value.getName());

        if (!initialize()) {
            Logging.warn("IntraSolver", "Failed to initialize intraContext: " + funcNode.value.getName());
            return;
        }

        visitor.prepare();
        visitor.run();

        Logging.debug("IntraSolver", "Solved function: " + funcNode.value.getName());
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
        Logging.trace("IntraSolver", "Add traced symbol: " + highSymbol.getName());
    }

    public void addTracedVarnode(Varnode vn) {
        tracedVarnodes.add(vn);
        Logging.trace("IntraSolver", "Add traced varnode: " + vn.toString());
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initDataFlowFacts() {
        for (var symbol: tracedSymbols) {
            Logging.trace("IntraSolver", "Candidate HighSymbol: " + symbol.getName());

            NMAE expr;
            Skeleton skeleton;
            DataType decompilerDT;

            // Create the NMAE and Skeleton for the HighSymbol
            if (symbol.isGlobal()) {
                expr = new NMAEManager.Builder().global(HighSymbolHelper.getGlobalHighSymbolAddr(symbol), symbol).build();
                exprManager.addExprAttribute(expr, NMAE.Attribute.GLOBAL);
                decompilerDT = symbol.getDataType();
            } else {
                expr = new NMAEManager.Builder().rootSymbol(symbol).build();
                decompilerDT = funcNode.getDecompilerInferredDT(symbol.getStorage());
                if (decompilerDT == null) {
                    decompilerDT = symbol.getDataType();
                }

                if (funcNode.parameters.contains(symbol)) {
                    expr.isParameter = true;
                }
            }

            if (DataTypeHelper.isCompositeOrArray(decompilerDT)) {
                // Initialize Stack-allocated Composite DataType
                decompilerDT = DataTypeHelper.getTypeDefBaseDataType(decompilerDT);
                if (decompilerDT instanceof Array array) {
                    expr = getExprForStackAllocated(expr);
                    exprManager.addExprAttribute(expr, NMAE.Attribute.ARRAY);
                    skeleton = exprManager.getOrCreateSkeleton(expr);
                    skeleton.setComposite(true);
                    skeleton.setSizeFromExpr(array.getLength(), expr);
                    skeleton.addPolymorphicType(array);

                    Logging.debug("IntraSolver", String.format("Found Array: %s -> %s", expr, decompilerDT.getName()));
                }
                else if (decompilerDT instanceof Structure structure) {
                    expr = getExprForStackAllocated(expr);
                    exprManager.addExprAttribute(expr, NMAE.Attribute.STRUCT);
                    skeleton = exprManager.getOrCreateSkeleton(expr);
                    skeleton.setComposite(true);
                    skeleton.setSizeFromExpr(structure.getLength(), expr);
                    skeleton.addPolymorphicType(structure);

                    Logging.debug("IntraSolver", String.format("Found Structure: %s -> %s", expr, decompilerDT.getName()));
                }
                else if (decompilerDT instanceof Union union) {
                    expr = getExprForStackAllocated(expr);
                    exprManager.addExprAttribute(expr, NMAE.Attribute.UNION);
                    skeleton = exprManager.getOrCreateSkeleton(expr);
                    skeleton.setComposite(true);
                    skeleton.setSizeFromExpr(union.getLength(), expr);
                    skeleton.addPolymorphicType(union);

                    Logging.debug("IntraSolver", String.format("Found Union: %s -> %s", expr, decompilerDT.getName()));
                }
            } else if (decompilerDT instanceof Pointer ptrDT) {
                // Initialize Pointer to Composite DataType
                if (DataTypeHelper.isPointerToCompositeDataType(ptrDT)) {
                    var pointTo = DataTypeHelper.getTypeDefBaseDataType(ptrDT.getDataType());
                    if (pointTo instanceof Structure structure) {
                        exprManager.addExprAttribute(expr, NMAE.Attribute.POINTER_TO_STRUCT);
                        skeleton = exprManager.getOrCreateSkeleton(expr);
                        skeleton.setComposite(true);
                        skeleton.setSizeFromExpr(structure.getLength(), expr);
                        skeleton.addPolymorphicType(structure);

                        Logging.debug("IntraSolver", String.format("Found Pointer to Struct: %s -> %s", expr, decompilerDT.getName()));
                    }
                    else if (pointTo instanceof Union union) {
                        exprManager.addExprAttribute(expr, NMAE.Attribute.POINTER_TO_UNION);
                        skeleton = exprManager.getOrCreateSkeleton(expr);
                        skeleton.setComposite(true);
                        skeleton.setSizeFromExpr(union.getLength(), expr);
                        skeleton.addPolymorphicType(union);

                        Logging.debug("IntraSolver", String.format("Found Pointer to Union: %s -> %s", expr, decompilerDT.getName()));
                    }
                }
            } else {
                Logging.trace("IntraSolver", String.format("Found Primitive: %s -> %s", expr.toString(), decompilerDT.getName()));
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
            Logging.trace("IntraSolver", "New " + vn + " -> " + curDataFlowFact);
        }
        addTracedVarnode(vn);
    }

    public KSet<NMAE> getOrCreateDataFlowFacts(Varnode vn) {
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
        Logging.trace("IntraSolver", "Merge " + output + " -> " + outputFacts);
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
     * Add intra-function edges in the Type Flow Graph
     * @param from the source NMAE
     * @param to the target NMAE
     * @param edgeType the type of the edge
     */
    public void addIntraTFGEdges(NMAE from, NMAE to, TypeFlowGraph.EdgeType edgeType) {
        if (from.equals(to)) {
            return;
        }

        if (FunctionNode.isMergedVariableExpr(funcNode, from) || FunctionNode.isMergedVariableExpr(funcNode, to)) {
            Logging.debug("IntraSolver",
                    String.format("Skip adding TFG Edges between merged variables: %s and %s", from, to));
            return;
        }

        graphManager.addEdge(from, to, edgeType);
    }

    /**
     * NMAE -> Skeleton is a mapping indicating that the NMAE is pointed to
     * a Composite Type described by the Skeleton.
     * So, for stack-allocated variables, we need to create its reference.
     *
     * For example, `local_10` -> `&local_10[Composite]`
     *
     * @param baseExpr original stack-allocated NMAE
     * @return the reference NMAE
     */
    private NMAE getExprForStackAllocated(NMAE baseExpr) {
        return exprManager.reference(baseExpr);
    }
}