package blueprint.solver;

import blueprint.base.dataflow.AccessPointSet;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.constraints.ComplexTypeConstraint;
import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

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
    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public AccessPointSet apSet;
    public HashMap<SymbolExpr, ComplexTypeConstraint> symToConstraints;
    public UnionFind<SymbolExpr> symAliasMap;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.intraCtxMap = new HashMap<>();
        this.apSet = new AccessPointSet();
        this.symToConstraints = new HashMap<>();
        this.symAliasMap = new UnionFind<>();
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

    public void addAccessPoint(PcodeOp pcodeOp, SymbolExpr symExpr, TypeDescriptor type, boolean isLoad) {
        apSet.addAccessPoint(pcodeOp, symExpr, type, isLoad);
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

    public void updateSymbolAliasMap(SymbolExpr sym1, SymbolExpr sym2) {
        symAliasMap.union(sym1, sym2);
        Logging.debug(String.format("[Alias] %s -> %s", sym1, sym2));
    }

    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    // TODO: this method should be called after all functions are solved, now it is called after each function is solved for debugging
    public void buildConstraints() {
        // Step1: group all AccessPoints by the representative root symbol
        var rootExprToAPs = apSet.groupByRepresentativeRootSymbol();
        Set<SymbolExpr> visited = new HashSet<>();

        rootExprToAPs.forEach((rootExpr, APs) -> {
            if (visited.contains(rootExpr)) {
                return;
            }

            if (!rootExpr.isRootSymbol()) {
                Logging.error("The rootExpr is not a root symbol: " + rootExpr);
                return;
            }

            // Step2: merge the AccessPoints from the same alias cluster
            var mergedAPs = new HashSet<>(APs);
            var aliasCluster = symAliasMap.getCluster(rootExpr);
            Logging.debug("[Alias] " + aliasCluster);

            for (var aliasSym: aliasCluster) {
                if (aliasSym == rootExpr) {
                    continue;
                }
                var aliasAPs = rootExprToAPs.get(aliasSym);
                if (aliasAPs != null) {
                    mergedAPs.addAll(aliasAPs);
                }
            }

            // Step3: build the ComplexTypeConstraint
            var constraint = new ComplexTypeConstraint();

            // Step4: update the symToConstraints map according to the alias cluster
            for (var aliasSym: aliasCluster) {
                symToConstraints.put(aliasSym, constraint);
                visited.add(aliasSym);
                Logging.debug("[Alias] " + aliasSym + " -> " + constraint.getName());
            }

            constraint.buildConstraint(mergedAPs);
        });
    }


    public boolean isFunctionSolved(FunctionNode funcNode) {
        return intraCtxMap.containsKey(funcNode);
    }

    public void dumpIntraComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        for (var highSym: intraCtx.tracedSymbols) {
            var symExpr = new SymbolExpr.Builder().rootSymbol(highSym).build();
            var complexType = symToConstraints.get(symExpr);
            if (complexType != null) {
                Logging.info("[TypeConstraints] " + highSym.getName() + " -> " + complexType);
            }
        }
    }
}
