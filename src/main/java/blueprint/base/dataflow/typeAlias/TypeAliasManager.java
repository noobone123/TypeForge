package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr;
import blueprint.utils.Logging;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;

public class TypeAliasManager<T> {
    private final Set<TypeAliasGraph<T>> graphs;
    private final Map<T, TypeAliasGraph<T>> exprToGraph;

    public TypeAliasManager() {
        this.graphs = new HashSet<>();
        this.exprToGraph = new HashMap<>();
    }

    public void addEdge(T from, T to, TypeAliasGraph.EdgeType type) {
        TypeAliasGraph<T> fromGraph = exprToGraph.get(from);
        TypeAliasGraph<T> toGraph = exprToGraph.get(to);
        if (fromGraph == null && toGraph == null) {
            TypeAliasGraph<T> newGraph = new TypeAliasGraph<T>();
            newGraph.addEdge(from, to, type);
            exprToGraph.put(from, newGraph);
            exprToGraph.put(to, newGraph);
        } else if (fromGraph == null) {
            toGraph.addEdge(from, to, type);
            exprToGraph.put(from, toGraph);
        } else if (toGraph == null) {
            fromGraph.addEdge(from, to, type);
            exprToGraph.put(to, fromGraph);
        } else if (fromGraph != toGraph) {
            mergeGraphs(fromGraph, toGraph);
            fromGraph.addEdge(from, to, type);
        } else {
            // fromGraph == toGraph
            fromGraph.addEdge(from, to, type);
        }
    }

    /**
     * Merge graph2 into graph1 and remove graph2 from the manager
     * @param graph1 the graph to merge into
     * @param graph2 the graph to merge
     */
    public void mergeGraphs(TypeAliasGraph<T> graph1, TypeAliasGraph<T> graph2) {
        for (var node: graph2.getAdjList().keySet()) {
            exprToGraph.put(node, graph1);
        }

        graph1.getAdjList().putAll(graph2.getAdjList());
        graphs.remove(graph2);
        Logging.info("TypeAliasManager", String.format("Merge %s into %s", graph2, graph1));
    }


    public void removeNode(T node) {
        var graph = exprToGraph.get(node);
        if (graph != null) {
            graph.removeNode(node);
            splitGraph(graph);
        }
    }

    private void splitGraph(TypeAliasGraph<T> graph) {
        Set<TypeAliasGraph<T>> components = graph.getConnectedComponents();
        if (components.size() > 1) {
            graphs.remove(graph);
            for (var component: components) {
                graphs.add(component);
                for (var node: component.getAdjList().keySet()) {
                    exprToGraph.put(node, component);
                }
            }
            graphs.remove(graph);
        }
    }

    public TypeAliasGraph<T> getTypeAliasGraph(T node) {
        return exprToGraph.get(node);
    }

}
