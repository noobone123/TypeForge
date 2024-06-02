package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.constraints.PrimitiveTypeDescriptor;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr;

import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.HighSymbol;
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
        public HashSet<SymbolExpr> returnExprs;
        public int dataFlowFactKSize = 10;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
            this.returnExprs = new HashSet<>();
        }

        public void setReturnExpr(SymbolExpr expr) {
            this.returnExprs.add(expr);
        }

        public Set<SymbolExpr> getReturnExpr() {
            return this.returnExprs;
        }
    }

    public CallGraph callGraph;
    /** The workList queue of the whole program */
    public Queue<FunctionNode> workList;
    /** The set of solved functions */
    public Set<FunctionNode> solvedFunc;

    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public AccessPoints APs;
    public HashMap<SymbolExpr, TypeConstraint> symExprToConstraints;
    public HashSet<SymbolExpr> parsedSymExprs;
    public UnionFind<SymbolExpr> typeAlias;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.workList = new LinkedList<>();
        this.solvedFunc = new HashSet<>();
        this.intraCtxMap = new HashMap<>();
        this.APs = new AccessPoints();
        this.symExprToConstraints = new HashMap<>();
        this.parsedSymExprs = new HashSet<>();
        this.typeAlias = new UnionFind<>();
    }

    public void createIntraContext(FunctionNode funcNode) {
        IntraContext intraCtx = new IntraContext();
        intraCtxMap.put(funcNode, intraCtx);
    }

    public void addTracedSymbol(FunctionNode funcNode, HighSymbol highSymbol) {
        IntraContext intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Context", "Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        intraCtx.tracedSymbols.add(highSymbol);
    }

    public void addTracedVarnode(FunctionNode funcNode, Varnode vn) {
        var tracedVns = intraCtxMap.get(funcNode).tracedVarnodes;
        if (tracedVns.add(vn)) {
            Logging.debug("Context", "Add traced varnode: " + vn);
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
            Logging.error("Context", "Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        var curDataFlowFact = intraCtx.dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(intraCtx.dataFlowFactKSize));

        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("Context", "New " + vn + " -> " + curDataFlowFact);
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
            Logging.warn("Context", "Failed to get dataflow fact for " + input);
            return;
        }

        var outputFacts = dataFlowFacts.computeIfAbsent(output, k -> new KSet<>(intraCtx.dataFlowFactKSize));
        if (isStrongUpdate) {
            outputFacts.clear();
        }

        outputFacts.merge(inputFacts);
        Logging.debug("Context", "Merge " + output + " -> " + outputFacts);
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initIntraDataFlowFacts(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        // Update the interestedVn
        for (var symbol: intraCtx.tracedSymbols) {
            Logging.info("Context", "Candidate HighSymbol: " + symbol.getName());

            SymbolExpr expr;
            TypeConstraint constraint;
            var dataType = symbol.getDataType();
            if (symbol.isGlobal()) {
                expr = new SymbolExpr.Builder().global(symbol.getSymbol().getAddress(), symbol).build();
                expr.addAttribute(SymbolExpr.Attribute.GLOBAL);
                constraint = getConstraint(expr);
            } else {
                expr = new SymbolExpr.Builder().rootSymbol(symbol).build();
                if (dataType instanceof Array || dataType instanceof Structure || dataType instanceof Union) {
                    expr = SymbolExpr.reference(this, expr);
                }
                constraint = getConstraint(expr);
            }

            if (dataType instanceof Array array) {
                Logging.info("Context", "Found decompiler recovered Array " + dataType.getName());
                expr.addAttribute(SymbolExpr.Attribute.STACK_ARRAY);
                constraint.setTotalSize(array.getLength());
                constraint.setElementSize(array.getElementLength());
            }
            else if (dataType instanceof Structure structure) {
                Logging.info("Context", "Found decompiler recovered Structure " + dataType.getName());
                expr.addAttribute(SymbolExpr.Attribute.STACK_STRUCT);
                constraint.setTotalSize(structure.getLength());
                for (var field: structure.getComponents()) {
                    constraint.addOffsetTypeConstraint(field.getOffset(), new PrimitiveTypeDescriptor(field.getDataType()));
                }
            }
            else if (dataType instanceof Union union) {
                Logging.info("Context", "Found decompiler recovered Union " + dataType.getName());
                expr.addAttribute(SymbolExpr.Attribute.STACK_UNION);
                constraint.setTotalSize(union.getLength());
                for (var field: union.getComponents()) {
                    constraint.addOffsetTypeConstraint(field.getOffset(), new PrimitiveTypeDescriptor(field.getDataType()));
                }
            }

            // In some time, a HighSymbol may not have corresponding HighVariable due to some reasons:
            // 1. HighSymbol is not used in the function
            // 2. HighSymbol is used in the function, but ghidra's decompiler failed to find the HighVariable
            if (symbol.getHighVariable() == null) {
                Logging.warn("Context", funcNode.value.getName() + " -> HighSymbol: " + symbol.getName() + " has no HighVariable");
            } else {
                // Initialize the dataFlowFacts using the interested varnodes and add
                // all varnode instances of the HighVariable to the IntraContext's tracedVarnodes
                // TODO: this may cause flow-insensitive, ... we can improve it in the future
                for (var vn: symbol.getHighVariable().getInstances()) {
                    addTracedVarnode(funcNode, vn);
                    addNewSymbolExpr(funcNode, vn, expr);
                }
            }

        }
    }

    public boolean isTracedVn(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        return intraCtx.tracedVarnodes.contains(vn);
    }

    public KSet<SymbolExpr> getIntraDataFlowFacts(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        var res = intraCtx.dataFlowFacts.get(vn);
        if (res == null) {
            Logging.warn("Context", "Failed to get dataflow fact for " + vn);
            return null;
        }
        return res;
    }

    public void setTypeAlias(SymbolExpr sym1, SymbolExpr sym2) {
        if (!sym1.equals(sym2)) {
            typeAlias.union(sym1, sym2);
            Logging.info("Context", String.format("Set type alias: %s == %s", sym1, sym2));
        }
    }

    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void buildConstraints() {
        // Remove redundant APs
        APs.removeRedundantAPs(typeAlias);

        // Parsing all SymbolExpr in AccessPoints, which is collected from the PCodeVisitor,
        // and build the constraints for each SymbolExpr, store the constraints in `symExprToConstraints`
        for (var symExpr : APs.getMemoryAccessMap().keySet()) {
            parseMemAccessExpr(symExpr, null, 0);
        }

        for (var symExpr : APs.getArgAccessMap().keySet()) {
            parseArgAccessExpr(symExpr);
        }

        // merging Type according to the typeAlias
        mergeTypeAlias();

        // Remove meaningLess constraints
        var finalResult = new HashMap<SymbolExpr, TypeConstraint>();
        for (var symExpr : symExprToConstraints.keySet()) {
            var constraint = symExprToConstraints.get(symExpr);
            if (constraint.isMeaningful()) {
                finalResult.put(symExpr, constraint);
            } else {
                Logging.warn("Context", String.format("Remove meaningless Constraint_%s", constraint.getName()));
            }
        }

        symExprToConstraints = finalResult;

        for (var constraint : symExprToConstraints.values()) {
            constraint.build();
        }

        Logging.info("Context", "Build constraints done.");
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
                        Logging.info("Context", "Merging " + aliasSym + ": " + constraint.getName() + " into " + mergedConstraint.getName());
                        mergedConstraint.merge(constraint);
                    }
                }

                for (var sym : cluster) {
                    symExprToConstraints.put(sym, mergedConstraint);
                    Logging.info("Context", String.format("Set %s -> %s", sym, mergedConstraint.getName()));
                    updated.add(sym);
                }
            }
            else {
                Logging.info("Context", symExpr + " is not type aliased with others.");
            }
        }
    }

    /**
     * Parse the Memory Access SymbolExpr and build the constraints for it.
     * @param expr the Expression to parse
     * @param parentTypeConstraint if the expr is a recursive dereference, the parentTypeConstraint is the constraint of the parent expr
     * @param derefDepth the dereference depth of the expr
     */
    private void parseMemAccessExpr(SymbolExpr expr, TypeConstraint parentTypeConstraint, long derefDepth) {
        if (expr == null) return;

        Logging.info("Context", String.format("Parsing MemAccessExpr %s, parentTypeConstraint: %s, derefDepth: %d", expr, parentTypeConstraint != null ? parentTypeConstraint.getName() : "null", derefDepth));

        var base = expr.getBase();
        var offset = expr.getOffset();
        var index = expr.getIndex();
        var scale = expr.getScale();
        long offsetValue = 0;

        // case: a or *(expr)
        if (expr.isRootSymExpr() || expr.isDereference()) {
            var constraint = getConstraint(expr);

            updateMemAccessConstraint(expr, parentTypeConstraint, derefDepth, offsetValue, constraint);

            if (expr.isDereference()) {
                parseMemAccessExpr(expr.getNestedExpr(), constraint, derefDepth + 1);
            }
        }

        else if (base != null) {
            var constraint = getConstraint(base);

            if (expr.hasOffset() && offset.isConst()) {
                offsetValue = offset.getConstant();
            }
            else if (expr.hasOffset() && !offset.isConst()) {
                Logging.warn("Context", String.format("Offset is not a constant: %s, Skipping...", expr));
                return;
            }

            updateMemAccessConstraint(expr, parentTypeConstraint, derefDepth, offsetValue, constraint);

            if (index != null && scale != null) {
                if (scale.isNoZeroConst()) {
                    constraint.setElementSize(scale.getConstant());
                }
            }
            if (base.isDereference()) {
                parseMemAccessExpr(base.getNestedExpr(), constraint, derefDepth + 1);
            }
        }
        else {
            Logging.warn("Context", String.format("Failed to parse MemAccessExpr %s", expr));
        }
    }

    /**
     * Parse the Argument Access SymbolExpr and build the constraints for it.
     * @param expr the Expression to parse
     */
    private void parseArgAccessExpr(SymbolExpr expr) {
        if (expr == null) return;
        Logging.info("Context", String.format("Parsing ArgAccessExpr %s", expr));

        var base = expr.getBase();
        var offset = expr.getOffset();
        if (base != null && offset != null &&
                offset.isNoZeroConst() && hasConstraint(expr)) {
            var constraint = getConstraint(base);
            long offsetValue = offset.getConstant();
            updateNestedConstraint(constraint, offsetValue, getConstraint(expr));
        }
    }


    private void updateMemAccessConstraint(SymbolExpr expr, TypeConstraint parentTypeConstraint, long derefDepth, long offsetValue, TypeConstraint constraint) {
        if (parentTypeConstraint == null) {
            updateFieldConstraint(constraint, offsetValue, APs.getMemoryAccessPoints(expr));
        } else {
            updateReferenceConstraint(constraint, offsetValue, parentTypeConstraint);
        }
        if (derefDepth > 0) {
            constraint.setPtrLevel(offsetValue, derefDepth);
        }
    }

    private void updateFieldConstraint(TypeConstraint currentTC, long offsetValue, Set<AccessPoints.AP> APs) {
        for (var ap: APs) {
            if (ap.accessType == AccessPoints.AccessType.LOAD || ap.accessType == AccessPoints.AccessType.STORE) {
                currentTC.addFieldConstraint(offsetValue, ap);
            }
        }
    }

    private void updateReferenceConstraint(TypeConstraint referencer, long offsetValue, TypeConstraint referencee) {
        referencee.addReferencedBy(offsetValue, referencer);
        referencer.addReferenceTo(offsetValue, referencee);
    }

    private void updateNestedConstraint(TypeConstraint nester, long offsetValue, TypeConstraint nestee) {
        nester.addNestTo(offsetValue, nestee);
        nester.addFieldAttr(offsetValue, TypeConstraint.Attribute.MAY_NESTED);
        nestee.addNestedBy(offsetValue, nester);
    }

    public TypeConstraint getConstraint(SymbolExpr symExpr) {
        TypeConstraint constraint;
        if (symExprToConstraints.containsKey(symExpr)) {
            constraint = symExprToConstraints.get(symExpr);
        } else {
            constraint = new TypeConstraint();
            symExprToConstraints.put(symExpr, constraint);
            Logging.debug("Context", String.format("Create Constraint_%s for %s", constraint.shortUUID, symExpr));
        }
        Logging.debug("Context", String.format("Get Constraint_%s for %s", constraint.shortUUID, symExpr));
        return constraint;
    }

    public AccessPoints getAccessPoints() {
        return APs;
    }

    public boolean hasConstraint(SymbolExpr symExpr) {
        return symExprToConstraints.containsKey(symExpr);
    }

    public boolean isFunctionSolved(FunctionNode funcNode) {
        return solvedFunc.contains(funcNode);
    }

    public void dumpResults() {
        String workingDir = System.getProperty("user.dir");
        Logging.info("Context", "Current working directory: " + workingDir);

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
            Logging.info("Context", "Constraints dumped to " + outputFile.getPath());

            mapper2.writerWithDefaultPrettyPrinter().writeValue(outputFile2, root2);
            Logging.info("Context", "Metadata dumped to " + outputFile2.getPath());

        } catch (IOException e) {
            Logging.error("Context", "Error writing JSON to file" + e.getMessage());
        }
    }
}
