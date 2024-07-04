package blueprint.base.dataflow.typeAlias;

import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.utils.Logging;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.io.FileWriter;
import java.util.*;

public class TypeAliasPathManager<T> {
    public TypeAliasGraph<T> graph;
    public boolean hasSrcSink = true;
    public final Set<T> source;
    public final Set<T> sink;

    public final Set<TypeAliasPath<T>> allPaths;
    public final Map<T, Set<TypeAliasPath<T>>> nodeToPathsMap;
    public final Map<T, Map<T, Set<TypeAliasPath<T>>>> srcSinkToPathsMap;

    public TypeAliasPathManager(TypeAliasGraph<T> graph) {
        this.graph = graph;
        this.source = new HashSet<>();
        this.sink = new HashSet<>();
        this.allPaths = new HashSet<>();
        this.nodeToPathsMap = new HashMap<>();
        this.srcSinkToPathsMap = new HashMap<>();
    }

    public void build() {
        findSources();
        findSinks();
        if (source.isEmpty() || sink.isEmpty()) {
            hasSrcSink = false;
            return;
        }

        if (hasSrcSink) {
            findAllPathFromSrcToSink();
        }

        for (var path: allPaths) {
            updateNodeToPathsMap(path);
        }
    }

    /** This Function should be called after all Graph's pathManager built */
    public void tryMergeByPath(SymbolExprManager exprManager) {
        var workList = new LinkedList<>(allPaths);

        while (!workList.isEmpty()) {
            var path = workList.poll();
            Logging.info("TypeAliasPathManager", "============================================== start ==============================================\n");
            Logging.info("TypeAliasPathManager", String.format("Try merge by path: %s", path));
            var hasConflict = path.tryMergeByPath(exprManager);
            if (hasConflict.isPresent()) {
                var conflictNode = hasConflict.get();
                // Split Path
                var splitPaths = path.splitPathFromNode(conflictNode);
                var firstPath = splitPaths.getKey();
                var secondPath = splitPaths.getValue();

                Logging.info("TypeAliasPathManager", String.format("Split new path: %s", firstPath));
                Logging.info("TypeAliasPathManager", String.format("Split new path: %s", secondPath));

                // Update related data structures
                updateNewPath(firstPath);
                updateNewPath(secondPath);

                // Add new paths into workList
                workList.add(firstPath);
                workList.add(secondPath);
            }
            Logging.info("TypeAliasPathManager", "============================================== end ==============================================\n");
        }
        // TODO: dump finalConstraint into paths
        // TODO: remove redundant Paths (finalTypeConstraint is Empty)
    }

    public void findSources() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) == 0 && graph.getGraph().outDegreeOf(vertex) > 0) {
                source.add(vertex);
            }
        }
    }

    public void findSinks() {
        for (T vertex : graph.getGraph().vertexSet()) {
            if (graph.getGraph().inDegreeOf(vertex) > 0 && graph.getGraph().outDegreeOf(vertex) == 0) {
                sink.add(vertex);
            }
        }
    }

    public void findAllPathFromSrcToSink() {
        for (T src: source) {
            for (T sk: sink) {
                var allPaths = new AllDirectedPaths<>(graph.getGraph()).getAllPaths(src, sk, true, Integer.MAX_VALUE);
                for (var path: allPaths) {
                    TypeAliasPath<T> typeAliasPath = new TypeAliasPath<>(path);
                    this.allPaths.add(typeAliasPath);
                    srcSinkToPathsMap.computeIfAbsent(src, k -> new HashMap<>()).computeIfAbsent(sk, k -> new HashSet<>()).add(typeAliasPath);
                }
            }
        }
        Logging.info("TypeAliasPathManager", String.format("Found %d paths from sources to sinks", allPaths.size()));
    }


    public void updateNewPath(TypeAliasPath<T> path) {
        allPaths.add(path);
        srcSinkToPathsMap.computeIfAbsent(path.start, k -> new HashMap<>())
                .computeIfAbsent(path.end, k -> new HashSet<>())
                .add(path);
        updateNodeToPathsMap(path);
    }


    public void updateNodeToPathsMap(TypeAliasPath<T> path) {
        for (var node: path.nodes) {
            nodeToPathsMap.computeIfAbsent(node, k -> new HashSet<>()).add(path);
        }
    }

    public Set<TypeAliasPath<T>> getAllPathContainsNode(T node) {
        return nodeToPathsMap.get(node);
    }

    public void dump(FileWriter writer) throws Exception {
        if (!hasSrcSink) {
            return;
        }
        writer.write(String.format("Graph: %s\n", graph));
        for (var src: source) {
            writer.write(String.format("\tSource: %s\n", src));
            for (var sk: sink) {
                var paths = srcSinkToPathsMap.get(src).get(sk);
                if (paths == null) {
                    continue;
                }
                writer.write(String.format("\t\tSink: %s\n", sk));
                for (var path: paths) {
                    writer.write(String.format("\t\t\tPath: %s\n", path));
                }
            }
        }
        writer.write("\n");
    }
}
