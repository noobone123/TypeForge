package blueprint.base.dataflow.typeAlias;

import com.contrastsecurity.sarif.Edge;
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
        INDIRECT
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
        int threshold = 3;
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

    // TODO: result is wrong, check correctness of getComponents and checkOverlap
    public Set<T> checkTypeAgnosticParams(Set<T> candidates, Map<T, TypeConstraint> nodeToConstraint) {
        // step1: make a copy of current graph
        TypeAliasGraph<T> copyGraph = createCopy();

        // step2: remove all CALL edges to T in candidates
        var candidateToSrc = new HashMap<T, Set<T>>();
        for (T dst: candidates) {
            for (T src: new HashSet<>(copyGraph.graph.vertexSet())) {
                TypeAliasEdge edge = copyGraph.graph.getEdge(src, dst);
                if (edge != null && edge.getType() == EdgeType.CALL) {
                    copyGraph.removeEdge(src, dst);
                    candidateToSrc.computeIfAbsent(dst, k -> new HashSet<>()).add(src);
                }
            }
        }

        // step3: generate subGraphs from the copyGraph
        var subGraphs = copyGraph.getConnectedComponents();

        // step4: merge constraints for each subGraph
        for (var graph: subGraphs) {
            var mergedConstraint = new TypeConstraint();
            for (T node: graph) {
                TypeConstraint constraint = nodeToConstraint.get(node);
                if (constraint != null) {
                    mergedConstraint.merge(constraint);
                    nodeToConstraint.put(node, mergedConstraint);
                }
            }
        }

        // step5: check for overlap
        Set<T> typeAgnosticParams = new HashSet<>();
        for (var entry: candidateToSrc.entrySet()) {
            var dst = entry.getKey();
            var srcs = entry.getValue();
            boolean hasOverlap = false;

            List<T> srcList = new ArrayList<>(srcs);
            outerLoop:
            for (int i = 0; i < srcList.size(); i++) {
                var constraintI = nodeToConstraint.get(srcList.get(i));
                if (constraintI == null) continue;
                for (int j = i + 1; j < srcList.size(); j++) {
                    var constraintJ = nodeToConstraint.get(srcList.get(j));
                    if (constraintJ == null) continue;
                    if (constraintI.checkOverlap(constraintJ)) {
                        hasOverlap = true;
                        break outerLoop;
                    }
                }
            }

            if (hasOverlap) {
                Logging.warn("TypeAliasGraph", "Confirmed type agnostic param: " + dst);
                typeAgnosticParams.add(dst);
            }
        }

        return typeAgnosticParams;
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
            builder.append("  ").append(src).append(" -> ").append(dst)
                    .append(" [label=\"").append(edge.getType()).append("\"];\n");
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
