package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.constraints.ConstraintCollector;
import org.jgrapht.Graph;
import org.jgrapht.alg.connectivity.ConnectivityInspector;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.Graphs;

import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;

import java.util.*;

public class TypeAliasGraph<T> {
    public enum EdgeType {
        CALL,
        RETURN,
        DATAFLOW,
        REFERENCE,
        INDIRECT,
        MEMALIAS,
    }

    public static class TypeAliasEdge extends DefaultEdge {
        private final EdgeType type;

        public TypeAliasEdge(EdgeType type) {
            this.type = type;
        }

        public EdgeType getType() {
            return type;
        }

        @Override
        public String toString() {
            return type.toString();
        }
    }

    private final Graph<T, TypeAliasEdge> graph;
    private final UUID uuid;
    private final String shortUUID;

    public TypeAliasGraph() {
        graph = new DefaultDirectedGraph<>(TypeAliasEdge.class);
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
        Logging.debug("TypeAliasGraph", String.format("Create TypeAliasGraph_%s", shortUUID));
    }

    public String getShortUUID() {
        return shortUUID;
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        graph.addVertex(src);
        graph.addVertex(dst);
        graph.addEdge(src, dst, new TypeAliasEdge(edgeType));
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        graph.removeEdge(src, dst);
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Remove edge: %s ---> %s", shortUUID, src, dst));
    }

    public void removeNode(T node) {
        graph.removeVertex(node);
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Remove node: %s", shortUUID, node));
    }

    public int getNumNodes() {
        return graph.vertexSet().size();
    }

    public Set<T> getNodes() {
        return graph.vertexSet();
    }

    public Graph<T, TypeAliasEdge> getGraph() {
        return graph;
    }

    public void mergeGraph(TypeAliasGraph<T> other) {
        for (T vertex: other.getNodes()) {
            graph.addVertex(vertex);
        }

        Set<TypeAliasEdge> edges = other.getGraph().edgeSet();
        for (TypeAliasEdge edge: edges) {
            T src = other.getGraph().getEdgeSource(edge);
            T dst = other.getGraph().getEdgeTarget(edge);
            var EdgeType = edge.getType();

            TypeAliasEdge existingEdge = graph.getEdge(src, dst);
            if (existingEdge == null) {
                graph.addEdge(src, dst, new TypeAliasEdge(EdgeType));
            } else if (existingEdge.getType() != EdgeType) {
                Logging.warn("TypeAliasGraph", String.format("%s Merge conflict: %s ---> %s", other, src, dst));
            } else {
                continue;
            }
        }

        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Merge with %s", shortUUID, other));
    }

    public Set<T> findMayTypeAgnosticParams() {
        Set<T> mayTypeAgnosticParams = new HashSet<>();
        int threshold = 5;
        Map<T, Integer> calledCountMap = new HashMap<>();

        for (var edge: graph.edgeSet()) {
            if (edge.getType() == EdgeType.CALL) {
                T dst = graph.getEdgeTarget(edge);
                calledCountMap.put(dst, calledCountMap.getOrDefault(dst, 0) + 1);
            }
        }

        for (var entry: calledCountMap.entrySet()) {
            if (entry.getValue() >= threshold) {
                Logging.warn("TypeAliasGraph", "Found May type agnostic param: " + entry.getKey() + " called " + entry.getValue() + " times.");
                mayTypeAgnosticParams.add(entry.getKey());
            }
        }

        return mayTypeAgnosticParams;
    }


    public Set<T> checkTypeAgnosticParams(Set<T> candidates, Map<SymbolExpr, TypeConstraint> exprToConstraint) {
        TypeAliasGraph<T> copyGraph = createCopy();
        copyGraph.removeTypeAgnosticCallEdgesAndMerge(candidates, exprToConstraint);

        var mayTypeAgnosticParamToArgMap = new HashMap<T, Set<T>>();
        for (T dst: candidates) {
            var incomingEdges = new HashSet<>(graph.incomingEdgesOf(dst));
            for (var edge: incomingEdges) {
                if (edge.getType() == EdgeType.CALL) {
                    T src = graph.getEdgeSource(edge);
                    mayTypeAgnosticParamToArgMap.computeIfAbsent(dst, k -> new HashSet<>()).add(src);
                }
            }
        }

        Map<TypeConstraint, Map<TypeConstraint, Boolean>> overlapCache = new HashMap<>();

        Set<T> typeAgnosticParams = new HashSet<>();
        for (var entry: mayTypeAgnosticParamToArgMap.entrySet()) {
            var dst = entry.getKey();
            var args = entry.getValue();
            boolean hasOverlap = false;
            int argNoInterestCount = 0;

            List<T> srcList = new ArrayList<>(args);

            Logging.info("TypeAliasGraph", "Checking type agnostic param: " + dst);
            for (int i = 0; i < srcList.size(); i++) {
                var constraintI = exprToConstraint.get((SymbolExpr)srcList.get(i));
                for (int j = i + 1; j < srcList.size(); j++) {
                    var constraintJ = exprToConstraint.get((SymbolExpr)srcList.get(j));
                    Logging.info("TypeAliasGraph", String.format("Checking overlap between %s -> %s and %s -> %s", srcList.get(i), constraintI, srcList.get(j), constraintJ));
                    if (!constraintI.isInterested()) {
                        argNoInterestCount++;
                        Logging.debug("TypeAliasGraph", "Skip non-interested constraint: " + constraintI);
                        break;
                    } else if (constraintI == constraintJ) {
                        Logging.debug("TypeAliasGraph", "Skip same constraint");
                        continue;
                    } else if (overlapCache.containsKey(constraintI) && overlapCache.get(constraintI).containsKey(constraintJ)) {
                        hasOverlap = overlapCache.get(constraintI).get(constraintJ);
                        Logging.debug("TypeAliasGraph", String.format("Overlap cache hit: %s <-> %s : %s", constraintI, constraintJ, hasOverlap));
                        break;
                    } else if (overlapCache.containsKey(constraintJ) && overlapCache.get(constraintJ).containsKey(constraintI)) {
                        hasOverlap = overlapCache.get(constraintJ).get(constraintI);
                        Logging.debug("TypeAliasGraph", String.format("Overlap cache hit: %s <-> %s : %s", constraintJ, constraintI, hasOverlap));
                        break;
                    } else {
                        hasOverlap = constraintI.checkFieldConflict(constraintJ);
                        if (hasOverlap) {
                            overlapCache.computeIfAbsent(constraintI, k -> new HashMap<>()).put(constraintJ, true);
                            overlapCache.computeIfAbsent(constraintJ, k -> new HashMap<>()).put(constraintI, true);
                        } else {
                            overlapCache.computeIfAbsent(constraintI, k -> new HashMap<>()).put(constraintJ, false);
                            overlapCache.computeIfAbsent(constraintJ, k -> new HashMap<>()).put(constraintI, false);
                        }
                        Logging.debug("TypeAliasGraph", String.format("Overlap between %s -> %s and %s -> %s : %s", srcList.get(i), constraintI, srcList.get(j), constraintJ, hasOverlap));
                        break;
                    }
                }

                if (hasOverlap) {
                    break;
                }
            }

            // TODO: How to check if Type Agnostic ...
            if (hasOverlap) {
                Logging.info("TypeAliasGraph", "Confirmed type agnostic param: " + dst);
                typeAgnosticParams.add(dst);
            } else {
                Logging.info("TypeAliasGraph", "Arg no interest count: " + argNoInterestCount);
                Logging.info("TypeAliasGraph", "Src list size: " + srcList.size());
                if (argNoInterestCount / (double)srcList.size() > 0.2) {
                    Logging.info("TypeAliasGraph", "Confirmed type agnostic param: " + dst);
                    typeAgnosticParams.add(dst);
                }
            }
        }

        return typeAgnosticParams;
    }

    public void removeTypeAgnosticCallEdgesAndMerge(Set<T> candidates, Map<SymbolExpr, TypeConstraint> exprToConstraint) {
        for (var dst: candidates) {
            var incomingEdges = new HashSet<>(graph.incomingEdgesOf(dst));
            for (var edge: incomingEdges) {
                if (edge.getType() == EdgeType.CALL) {
                    T src = graph.getEdgeSource(edge);
                    removeEdge(src, dst);
                }
            }
        }

        var subGraphs = getConnectedComponents();

        for (var graph: subGraphs) {
            mergeNodesConstraints(graph, exprToConstraint);
        }
    }

    public void mergeNodesConstraints(Set<T> mergedNodes, Map<SymbolExpr, TypeConstraint> exprToConstraint) {
        var mergedConstraint = new TypeConstraint();
        for (T node: mergedNodes) {
            TypeConstraint constraint = exprToConstraint.get((SymbolExpr)node);
            if (constraint != null) {
                mergedConstraint.merge(constraint);
                Logging.debug("TypeAliasGraph", String.format("Merge %s Constraint: Constraint_%s <- Constraint_%s", node, mergedConstraint.getName(), constraint.getName()));
            }
            exprToConstraint.put((SymbolExpr)node, mergedConstraint);
            Logging.debug("TypeAliasGraph", String.format("Set %s -> %s", node, mergedConstraint));
        }
    }


    public List<Set<T>> getConnectedComponents() {
        ConnectivityInspector<T, TypeAliasEdge> inspector = new ConnectivityInspector<>(graph);
        var result = inspector.connectedSets();

        for (var component: result) {
            Logging.debug("TypeAliasGraph", "Connected component: " + component);
        }

        return result;
    }

    public String toGraphviz() {
        StringBuilder builder = new StringBuilder();
        builder.append("digraph TypeAliasGraph_").append(shortUUID).append(" {\n");
        for (TypeAliasEdge edge : graph.edgeSet()) {
            T src = graph.getEdgeSource(edge);
            T dst = graph.getEdgeTarget(edge);
            builder.append("  \"").append(src).append("\" -> \"").append(dst)
                    .append("\" [label=\"").append(edge.getType()).append("\"];\n");
        }
        builder.append("}");
        return builder.toString();
    }

    public TypeAliasGraph<T> createCopy() {
        Logging.debug("TypeAliasGraph", "Create copy of " + this);
        TypeAliasGraph<T> copy = new TypeAliasGraph<>();
        Graphs.addGraph(copy.graph, this.graph);
        return copy;
    }

    @Override
    public String toString() {
        return "TypeAliasGraph_" + shortUUID;
    }
}
