package blueprint.base.dataflow.typeAlias;

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

    private final Set<T> nodes;
    private final Map<T, Map<T, EdgeType>> forwardAdjMap;
    private final Map<T, Map<T, EdgeType>> backwardAdjMap;
    private final UUID uuid;
    private final String shortUUID;

    public TypeAliasGraph() {
        nodes = new HashSet<>();
        forwardAdjMap = new HashMap<>();
        backwardAdjMap = new HashMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
        Logging.debug("TypeAliasGraph", String.format("Create TypeAliasGraph_%s", shortUUID));
    }

    public String getShortUUID() {
        return shortUUID;
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        forwardAdjMap.computeIfAbsent(src, k -> new HashMap<>()).put(dst, edgeType);
        backwardAdjMap.computeIfAbsent(dst, k -> new HashMap<>()).put(src, edgeType);
        nodes.add(src);
        nodes.add(dst);
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        var forwardEdges = forwardAdjMap.get(src);
        if (forwardEdges != null) {
            forwardEdges.remove(dst);
            Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Remove forward edge: %s ---> %s", shortUUID, src, dst));
            if (forwardEdges.isEmpty()) {
                forwardAdjMap.remove(src);
            }
        }

        var backwardEdges = backwardAdjMap.get(dst);
        if (backwardEdges != null) {
            backwardEdges.remove(src);
            Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Remove backward edge: %s <--- %s", shortUUID, dst, src));
            if (backwardEdges.isEmpty()) {
                backwardAdjMap.remove(dst);
            }
        }

        // TODO: ifIsolatedNode, remove node?
    }

    public void removeNode(T node) {
        nodes.remove(node);
        forwardAdjMap.remove(node);
        backwardAdjMap.remove(node);
        for (var edges: forwardAdjMap.values()) {
            edges.remove(node);
        }
        for (var edges: backwardAdjMap.values()) {
            edges.remove(node);
        }
    }

    public int getNumNodes() {
        return nodes.size();
    }

    public Set<T> getNodes() {
        return nodes;
    }

    public Map<T, Map<T, EdgeType>> getForwardAdjMap() {
        return forwardAdjMap;
    }

    public Map<T, Map<T, EdgeType>> getBackwardAdjMap() {
        return backwardAdjMap;
    }

    private boolean isIsolatedNode(T node) {
        return !forwardAdjMap.containsKey(node) && !backwardAdjMap.containsKey(node);
    }

    public Set<TypeAliasGraph<T>> getConnectedComponents() {
        Set<TypeAliasGraph<T>> components = new HashSet<>();
        Set<T> visited = new HashSet<>();

        for (var node: nodes) {
            if (!visited.contains(node)) {
                TypeAliasGraph<T> component = new TypeAliasGraph<>();
                dfs(node, visited, component);
                components.add(component);
            }
        }

        for (var component: components) {
            Logging.debug("TypeAliasGraph", String.format("Component %s: %s", component, component.getNodes()));
        }

        return components;
    }

    private void dfs(T node, Set<T> visited, TypeAliasGraph<T> component) {
        Stack<T> stack = new Stack<>();
        stack.push(node);

        while (!stack.isEmpty()) {
            T curNode = stack.pop();
            if (!visited.contains(curNode)) {
                visited.add(curNode);
                component.nodes.add(curNode);
                Logging.debug("TypeAliasGraph", String.format("Added node to component: %s", curNode));

                for (var neighbor : forwardAdjMap.getOrDefault(curNode, Collections.emptyMap()).entrySet()) {
                    component.addEdge(curNode, neighbor.getKey(), neighbor.getValue());
                    stack.push(neighbor.getKey());
                }
                for (var neighbor : backwardAdjMap.getOrDefault(curNode, Collections.emptyMap()).entrySet()) {
                    component.addEdge(neighbor.getKey(), curNode, neighbor.getValue());
                    stack.push(neighbor.getKey());
                }
            }
        }
    }

    public Set<T> findMayTypeAgnosticParams() {
        Set<T> mayTypeAgnosticParams = new HashSet<>();
        int threshold = 3;
        Map<T, Integer> calledCountMap = new HashMap<>();

        for (Map<T, EdgeType> edges : forwardAdjMap.values()) {
            for (Map.Entry<T, EdgeType> entry : edges.entrySet()) {
                if (entry.getValue() == EdgeType.CALL) {
                    calledCountMap.put(entry.getKey(), calledCountMap.getOrDefault(entry.getKey(), 0) + 1);
                }
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
        for (var dst: candidates) {
            for (var src: new HashSet<>(copyGraph.forwardAdjMap.keySet())) {
                if (copyGraph.forwardAdjMap.get(src).get(dst) == EdgeType.CALL) {
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
            for (T node: graph.getNodes()) {
                mergedConstraint.merge(nodeToConstraint.get(node));
                nodeToConstraint.put(node, mergedConstraint);
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


    public String toGraphviz() {
        StringBuilder builder = new StringBuilder();
        builder.append("digraph TypeAliasGraph_").append(shortUUID).append(" {\n");
        for (var entry : forwardAdjMap.entrySet()) {
            for (var edge : entry.getValue().entrySet()) {
                builder.append("  \"").append(entry.getKey()).append("\" -> \"")
                        .append(edge.getKey()).append("\" [label=\"").append(edge.getValue()).append("\"];\n");
            }
        }
        builder.append("}\n");
        return builder.toString();
    }


    public TypeAliasGraph<T> createCopy() {
        Logging.debug("TypeAliasGraph", "Create copy of " + this);
        TypeAliasGraph<T> copy = new TypeAliasGraph<>();
        copy.nodes.addAll(nodes);
        // deep copy adjMap
        for (var entry : forwardAdjMap.entrySet()) {
            for (var edge : entry.getValue().entrySet()) {
                copy.addEdge(entry.getKey(), edge.getKey(), edge.getValue());
            }
        }
        return copy;
    }

    /**
     * Merge other graph into this graph
     * @param other the graph to merge
     */
    public void mergeGraph(TypeAliasGraph<T> other) {
        // merge nodes
        nodes.addAll(other.nodes);

        // Merge forward edges
        for (var entry: other.forwardAdjMap.entrySet()) {
            T src = entry.getKey();
            Map<T, EdgeType> existingEdges = forwardAdjMap.computeIfAbsent(src, k -> new HashMap<>());
            for (var edge: entry.getValue().entrySet()) {
                T dst = edge.getKey();
                var edgeType = edge.getValue();
                if (existingEdges.containsKey(dst) && existingEdges.get(dst) != edgeType) {
                    var oldEdgeType = existingEdges.get(dst);
                    Logging.warn("TypeAliasGraph", String.format("Conflict edge type: %s --%s---> %s, %s --%s---> %s", src, oldEdgeType, dst, src, edgeType, dst));
                } else {
                    existingEdges.put(dst, edgeType);
                }
            }
        }

        // Merge backward edges
        for (var entry : other.backwardAdjMap.entrySet()) {
            T dst = entry.getKey();
            Map<T, EdgeType> existingEdges = backwardAdjMap.computeIfAbsent(dst, k -> new HashMap<>());
            for (var edge : entry.getValue().entrySet()) {
                T src = edge.getKey();
                EdgeType edgeType = edge.getValue();
                if (existingEdges.containsKey(src) && existingEdges.get(src) != edgeType) {
                    EdgeType oldEdgeType = existingEdges.get(src);
                    Logging.warn("TypeAliasGraph", String.format("Conflict edge type: %s <--%s-- %s, %s <--%s-- %s", dst, oldEdgeType, src, dst, edgeType, src));
                } else {
                    existingEdges.put(src, edgeType);
                }
            }
        }

        Logging.info("TypeAliasGraph", String.format("Merge TypeAliasGraph: %s <-- %s", this, other));
    }


    @Override
    public String toString() {
        return "TypeAliasGraph_" + shortUUID;
    }
}
