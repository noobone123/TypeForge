package blueprint.base.dataflow.typeAlias;

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

    private final Map<T, Map<T, EdgeType>> adjMap;
    private final UUID uuid;
    private final String shortUUID;

    public TypeAliasGraph() {
        adjMap = new HashMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
        Logging.debug("TypeAliasGraph", String.format("Create TypeAliasGraph_%s", shortUUID));
    }

    public String getShortUUID() {
        return shortUUID;
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        adjMap.computeIfAbsent(src, k -> new HashMap<>()).put(dst, edgeType);
        Logging.debug("TypeAliasGraph", String.format("TypeAliasGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        var edges = adjMap.get(src);
        if (edges != null) {
            edges.remove(dst);
            if (edges.isEmpty()) {
                adjMap.remove(src);
            }
        }
    }

    public void removeNode(T node) {
        adjMap.remove(node);
        for (var edges: adjMap.values()) {
            edges.remove(node);
        }
    }

    public int getNumNodes() {
        return adjMap.size();
    }

    public Set<T> getNodes() {
        Set<T> nodes = new HashSet<>(adjMap.keySet());
        for (var edges: adjMap.values()) {
            nodes.addAll(edges.keySet());
        }
        return nodes;
    }

    public Map<T, Map<T, EdgeType>> getAdjMap() {
        return adjMap;
    }

    public Set<TypeAliasGraph<T>> getConnectedComponents() {
        Set<TypeAliasGraph<T>> components = new HashSet<>();
        Set<T> visited = new HashSet<>();

        for (var node: adjMap.keySet()) {
            if (!visited.contains(node)) {
                TypeAliasGraph<T> component = new TypeAliasGraph<>();
                dfs(node, visited, component);
                components.add(component);
            }
        }

        return components;
    }

    private void dfs(T node, Set<T> visited, TypeAliasGraph<T> component) {
        Stack<T> stack = new Stack<>();
        stack.push(node);
        visited.add(node);

        while (!stack.isEmpty()) {
            var curNode = stack.pop();
            if (!visited.contains(curNode)) {
                visited.add(curNode);
                for (var neighbor: adjMap.getOrDefault(curNode, Collections.emptyMap()).entrySet()) {
                    component.addEdge(curNode, neighbor.getKey(), neighbor.getValue());
                    stack.push(neighbor.getKey());
                }
            }
        }
    }


    public String toGraphviz() {
        StringBuilder builder = new StringBuilder();
        builder.append("digraph TypeAliasGraph_").append(shortUUID).append(" {\n");
        for (var entry : adjMap.entrySet()) {
            for (var edge : entry.getValue().entrySet()) {
                builder.append("  \"").append(entry.getKey()).append("\" -> \"")
                        .append(edge.getKey()).append("\" [label=\"").append(edge.getValue()).append("\"];\n");
            }
        }
        builder.append("}\n");
        return builder.toString();
    }


    @Override
    public String toString() {
        return "TypeAliasGraph_" + shortUUID;
    }
}
