package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr;

import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;


/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 */
public class Context {

    public static class IntraContext {
        /** The candidate HighSymbols that need to collect data-flow facts */
        public final HashSet<HighSymbol> tracedSymbols;
        public final HashSet<Varnode> tracedVarnodes;

        /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
        public HashMap<Varnode, KSet<SymbolExpr>> dataFlowFacts;
        public int dataFlowFactKSize = 10;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
        }
    }

    public CallGraph callGraph;
    /** The workList queue of the whole program */
    public Queue<FunctionNode> workList;
    /** The set of solved functions */
    public Set<FunctionNode> solvedFunc;

    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public AccessPoints AP;
    public HashMap<SymbolExpr, TypeConstraint> symExprToConstraints;
    public UnionFind<SymbolExpr> typeAlias;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.solvedFunc = new HashSet<>();
        this.intraCtxMap = new HashMap<>();
        this.AP = new AccessPoints();
        this.symExprToConstraints = new HashMap<>();
        this.typeAlias = new UnionFind<>();
    }

    public void createIntraContext(FunctionNode funcNode) {
        IntraContext intraCtx = new IntraContext();
        intraCtxMap.put(funcNode, intraCtx);
    }

    public void addTracedSymbol(FunctionNode funcNode, HighSymbol highSymbol) {
        IntraContext intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        intraCtx.tracedSymbols.add(highSymbol);
    }

    public void addTracedVarnode(FunctionNode funcNode, Varnode vn) {
        var tracedVns = intraCtxMap.get(funcNode).tracedVarnodes;
        if (tracedVns.add(vn)) {
            Logging.debug("[DataFlow] Add traced varnode: " + vn);
        }
    }

    /**
     * create a new SymbolExpr and add it to the dataFlowFacts
     * @param funcNode the current function node
     * @param vn the varnode which holds the dataflow fact
     * @param symbolExpr the new symbolExpr
     */
    public void addNewSymbolExpr(FunctionNode funcNode, Varnode vn, SymbolExpr symbolExpr) {
        var intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        var curDataFlowFact = intraCtx.dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(intraCtx.dataFlowFactKSize));

        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("[DataFlow] New " + vn + " -> " + curDataFlowFact);
        }
    }


    /**
     * Merge the dataflow facts from input to output
     * @param funcNode the current function node
     * @param input the input varnode
     * @param output the output varnode
     * @param isStrongUpdate if true, the output varnode's dataflow facts will be cleared before merging
     */
    public void mergeSymbolExpr(FunctionNode funcNode, Varnode input, Varnode output, boolean isStrongUpdate) {
        var intraCtx = intraCtxMap.get(funcNode);
        assert intraCtx != null;
        var dataFlowFacts = intraCtx.dataFlowFacts;
        var inputFacts = dataFlowFacts.get(input);

        if (inputFacts == null) {
            Logging.warn("Failed to get dataflow fact for " + input);
            return;
        }

        var outputFacts = dataFlowFacts.computeIfAbsent(output, k -> new KSet<>(intraCtx.dataFlowFactKSize));
        if (isStrongUpdate) {
            outputFacts.clear();
        }

        outputFacts.merge(inputFacts);
        Logging.debug("[DataFlow] Merge " + output + " -> " + outputFacts);
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initIntraDataFlowFacts(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        // Update the interestedVn
        for (var symbol: intraCtx.tracedSymbols) {
            var highVar = symbol.getHighVariable();
            Logging.info("Candidate HighSymbol: " + symbol.getName());

            // If a HighSymbol (like a parameter) is not be used in the function, it can not hold a HighVariable
            if (highVar == null) {
                Logging.warn(funcNode.value.getName() + " -> HighSymbol: " + symbol.getName() + " has no HighVariable");
                continue;
            }

            // Initialize the dataFlowFacts using the interested varnodes and add
            // all varnode instances of the HighVariable to the IntraContext's tracedVarnodes
            // TODO: this may cause flow-insensitive, ... we can improve it in the future
            for (var vn: highVar.getInstances()) {
                addTracedVarnode(funcNode, vn);
                var symExpr = new SymbolExpr.Builder()
                                .rootSymbol(symbol)
                                .build();

                addNewSymbolExpr(funcNode, vn, symExpr);
            }
        }
    }

    public boolean isInterestedVn(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        return intraCtx.tracedVarnodes.contains(vn);
    }

    public void addAccessPoint(SymbolExpr symExpr, PcodeOp pcodeOp, TypeDescriptor type, AccessPoints.AccessType accType ) {
        AP.addAccessPoint(symExpr, pcodeOp, type, accType);
    }

    public KSet<SymbolExpr> getIntraDataFlowFacts(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        var res = intraCtx.dataFlowFacts.get(vn);
        if (res == null) {
            Logging.warn("Failed to get dataflow fact for " + vn);
            return null;
        }
        return res;
    }

    public void setTypeAlias(SymbolExpr sym1, SymbolExpr sym2) {
        if (!sym1.equals(sym2)) {
            typeAlias.union(sym1, sym2);
            Logging.info(String.format("[Alias] %s == %s", sym1, sym2));
        }
    }

    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void buildConstraints() {
        // Parsing all SymbolExpr collected from PCodeVisitor, save them into symExprToConstraints
        for (var symExpr : AP.getSymbolExprs()) {
            parseSymbolExpr(symExpr, null, 0);
        }

        // merging Type according to the typeAlias
        mergeTypeAlias();

        for (var constraint : symExprToConstraints.values()) {
            constraint.build();
        }

        Logging.info("[Constraint] Build constraints done.");
    }


    private void mergeTypeAlias() {
        HashSet<SymbolExpr> updated = new HashSet<>();
        var tmpSymExprToConstraints = new HashMap<>(symExprToConstraints);

        for (var symExpr : tmpSymExprToConstraints.keySet()) {
            if (updated.contains(symExpr)) {
                continue;
            }
            var cluster = typeAlias.getCluster(symExpr);
            if (cluster.size() > 1) {
                var mergedConstraint = new TypeConstraint();
                for (var aliasSym : cluster) {
                    var constraint = tmpSymExprToConstraints.get(aliasSym);
                    if (constraint != null) {
                        Logging.info("[Alias] Merging " + aliasSym + ": " + constraint.getName() + " into " + mergedConstraint.getName());
                        mergedConstraint.merge(constraint);
                    }
                }

                for (var sym : cluster) {
                    symExprToConstraints.put(sym, mergedConstraint);
                    updated.add(sym);
                }
            }
            else {
                Logging.info("[Alias] " + symExpr + " is not type aliased with others.");
            }
        }
    }


    private void parseSymbolExpr(SymbolExpr expr, TypeConstraint parentTypeConstraint, long derefDepth) {
        if (expr == null) return;

        Logging.info("[SymExpr] Parsing " + expr + ", parentTypeConstraint: " + (parentTypeConstraint != null ? parentTypeConstraint.getName() : "null")
                            + ", derefDepth: " + derefDepth);

        var base = expr.getBase();
        var offset = expr.getOffset();
        var index = expr.getIndex();
        var scale = expr.getScale();
        long offsetValue = 0;

        // case: a or *(expr)
        if (expr.isRootSymExpr() || expr.isDereference()) {
            var constraint = getConstraint(expr);
            updateConstraint(constraint, 0, parentTypeConstraint, AP.getAccessPoints(expr));

            if (derefDepth > 0) {
                constraint.setPtrLevel(offsetValue, derefDepth);
            }

            if (expr.isDereference()) {
                parseSymbolExpr(expr.getNestedExpr(), constraint, derefDepth + 1);
            }
        }

        else if (base != null) {
            var constraint = getConstraint(base);

            if (expr.hasOffset() && offset.isConst()) {
                offsetValue = offset.getConstant();
            }
            else if (expr.hasOffset() && !offset.isConst()) {
                Logging.warn("[SymExpr] Offset is not a constant: " + expr + ", Skipping...");
                return;
            }

            updateConstraint(constraint, offsetValue, parentTypeConstraint, AP.getAccessPoints(expr));

            if (derefDepth > 0) {
                constraint.setPtrLevel(offsetValue, derefDepth);
            }

            if (index != null && scale != null) {
                if (scale.isNoZeroConst()) {
                    constraint.setSize(scale.getConstant());
                }
            }

            if (base.isDereference()) {
                parseSymbolExpr(base.getNestedExpr(), constraint, derefDepth + 1);
            }
        }

        else {
            Logging.warn("[SymExpr] Unsupported SymbolExpr: " + expr + " , Skipping...");
        }
    }


    private void updateConstraint(TypeConstraint currentTC, long offsetValue, TypeConstraint parentTC, Set<AccessPoints. AP> APs) {
        if (parentTC != null) {
            parentTC.addReferencedBy(offsetValue, currentTC);
            currentTC.addReferenceTo(offsetValue, parentTC);
        }
        // If remove else {} block, the addFieldConstraint will be called
        // each time parsing a NestedExpr, this may cause the same APs to be added multiple times
        else {
            for (var ap: APs) {
                if (ap.accessType == AccessPoints.AccessType.LOAD || ap.accessType == AccessPoints.AccessType.STORE) {
                    currentTC.addFieldConstraint(offsetValue, ap);
                }
                else if (ap.accessType == AccessPoints.AccessType.ARGUMENT) {
                    if (offsetValue != 0) {
                        currentTC.addFieldConstraint(offsetValue, ap);
                        currentTC.addFieldTag(offsetValue, TypeConstraint.Attribute.MAY_NESTED);
                    }
                    else {
                        currentTC.addGlobalTag(TypeConstraint.Attribute.ARGUMENT);
                    }
                }
            }
        }
    }


    public TypeConstraint getConstraint(SymbolExpr symExpr) {
        TypeConstraint constraint = null;
        if (symExprToConstraints.containsKey(symExpr)) {
            constraint = symExprToConstraints.get(symExpr);
        } else {
            constraint = new TypeConstraint();
            symExprToConstraints.put(symExpr, constraint);
        }
        Logging.info("[SymExpr] Get " + symExpr + " -> " + constraint.getName());
        return constraint;
    }


    public boolean isFunctionSolved(FunctionNode funcNode) {
        return solvedFunc.contains(funcNode);
    }

    public void dumpResults() {
        String workingDir = System.getProperty("user.dir");
        Logging.info("Current working directory: " + workingDir);

        File outputDir = new File(System.getProperty("user.dir") + File.separator + "codes/blueprint/dummy");
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }

        // dump constraints to JSON file
        File outputFile = new File(outputDir, "constraints.json");
        var mapper = new ObjectMapper();
        var root = mapper.createObjectNode();
        symExprToConstraints.forEach((symExpr, constraint) -> {
            root.set("Constraint_" + constraint.shortUUID, constraint.getJsonObj(mapper));
        });

        // dump metadata to JSON file
        File outputFile2 = new File(outputDir, "metadata.json");
        var mapper2 = new ObjectMapper();
        var root2 = mapper2.createObjectNode();
        symExprToConstraints.forEach((symExpr, constraint) -> {
            var prefix = symExpr.prefix;
            var prefixNode = (ObjectNode) root2.get(prefix);
            if (prefixNode == null) {
                prefixNode = mapper2.createObjectNode();
                root2.set(prefix, prefixNode);
            }
            prefixNode.put(symExpr.getRepresentation(), "Constraint_" + constraint.shortUUID);
        });

        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, root);
            Logging.info("Constraints dumped to " + outputFile.getPath());

            mapper2.writerWithDefaultPrettyPrinter().writeValue(outputFile2, root2);
            Logging.info("Metadata dumped to " + outputFile2.getPath());

        } catch (IOException e) {
            Logging.error("Error writing JSON to file" + e.getMessage());
        }
    }
}
