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

    private final Map<T, Map<T, EdgeType>> adjList;
    private final UUID uuid;
    private final String shortUUID;

    public TypeAliasGraph() {
        adjList = new HashMap<>();
        uuid = UUID.randomUUID();
        shortUUID = uuid.toString().substring(0, 8);
    }

    public void addEdge(T src, T dst, EdgeType edgeType) {
        adjList.computeIfAbsent(src, k -> new HashMap<>()).put(dst, edgeType);
        Logging.info("TypeAliasGraph", String.format("TypeAliasGraph_%s Add edge: %s ---%s---> %s", shortUUID, src, edgeType, dst));
    }

    public void removeEdge(T src, T dst) {
        var edges = adjList.get(src);
        if (edges != null) {
            edges.remove(dst);
            if (edges.isEmpty()) {
                adjList.remove(src);
            }
        }
    }

    public void removeNode(T node) {
        adjList.remove(node);
        for (var edges: adjList.values()) {
            edges.remove(node);
        }
    }

    public int getNumNodes() {
        return adjList.size();
    }

    public Set<T> getNodes() {
        return adjList.keySet();
    }

    public Map<T, Map<T, EdgeType>> getAdjList() {
        return adjList;
    }

    public Set<TypeAliasGraph<T>> getConnectedComponents() {
        Set<TypeAliasGraph<T>> components = new HashSet<>();
        Set<T> visited = new HashSet<>();

        for (var node: adjList.keySet()) {
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

        while (!stack.isEmpty()) {
            var curNode = stack.pop();
            if (!visited.contains(curNode)) {
                visited.add(curNode);
                for (var neighbor: adjList.getOrDefault(curNode, Collections.emptyMap()).entrySet()) {
                    component.addEdge(curNode, neighbor.getKey(), neighbor.getValue());
                    stack.push(neighbor.getKey());
                }
            }
        }
    }

    @Override
    public String toString() {
        return "TypeAliasGraph_" + shortUUID;
    }
}
