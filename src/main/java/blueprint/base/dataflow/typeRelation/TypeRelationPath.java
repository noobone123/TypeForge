package blueprint.base.dataflow.typeRelation;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.constraints.TypeConstraint;
import blueprint.utils.Logging;
import org.jgrapht.GraphPath;

import java.util.*;

public class TypeRelationPath<T> {
    public final UUID uuid = UUID.randomUUID();
    public final String shortUUID = uuid.toString().substring(0, 8);
    public List<T> nodes;
    public List<TypeRelationGraph.TypeRelationEdge> edges;
    public List<TypeConstraint> backwardMergedConstraints;
    public List<TypeConstraint> forwardMergedConstraints;
    public TypeConstraint finalConstraint = null;
    public boolean hasConflict = false;
    public boolean noComposite = false;
    public T start;
    public T end;

    /**
     * Map[SUB_PATH_LENGTH, Map[HASH_CODE, SUB_PATH_NODES]]
     */
    public Map<Integer, Map<Integer, List<T>>> subPathsOfLengthWithHash = new HashMap<>();

    public TypeRelationPath(GraphPath<T, TypeRelationGraph.TypeRelationEdge> path) {
        // update nodes;
        this.nodes = path.getVertexList();
        this.edges = path.getEdgeList();

        this.backwardMergedConstraints = new ArrayList<>();
        this.forwardMergedConstraints = new ArrayList<>();

        this.start = nodes.get(0);
        this.end = nodes.get(nodes.size() - 1);
    }

    public TypeRelationPath(List<T> nodes, List<TypeRelationGraph.TypeRelationEdge> edges) {
        this.nodes = nodes;
        this.edges = edges;
        this.backwardMergedConstraints = new ArrayList<>();
        this.forwardMergedConstraints = new ArrayList<>();

        this.start = nodes.get(0);
        this.end = nodes.get(nodes.size() - 1);
    }

    public Map.Entry<TypeRelationPath<T>, TypeRelationPath<T>> splitPathFromNode(T conflictNode) {
        int startIndex = nodes.indexOf(conflictNode);
        var firstPathNodes = nodes.subList(0, startIndex);
        // TODO: first split path has last edge from last node ...
        var firstPathEdges = edges.subList(0, startIndex);
        var firstPath = new TypeRelationPath<>(firstPathNodes, firstPathEdges);
        var secondPathNodes = nodes.subList(startIndex, nodes.size());
        var secondPathEdges = edges.subList(startIndex, edges.size());
        var secondPath = new TypeRelationPath<>(secondPathNodes, secondPathEdges);
        return new AbstractMap.SimpleEntry<>(firstPath, secondPath);
    }

    public Optional<T> tryMergeOnPath(SymbolExprManager exprManager) {
        for (int i = 0; i < nodes.size(); i++) {
            T node = nodes.get(i);
            TypeConstraint curMergedCon;
            SymbolExpr curExpr = (SymbolExpr) node;
            TypeConstraint curExprCon = exprManager.getConstraint(curExpr);

            if (curExprCon == null) {
                Logging.warn("TypeAliasPath", String.format("Cannot find constraint for %s in path", node));
                curMergedCon = new TypeConstraint();
                Logging.info("TypeAliasPath", String.format("Created new Constraint %s for %s in path", curMergedCon, curExpr));
            } else {
                curMergedCon = new TypeConstraint(curExprCon);
                Logging.info("TypeAliasPath", String.format("Created new Constraint %s for %s in path", curMergedCon, curExpr));

                // If Current Expr is fieldAccessExpr, try to merge its memAliasExpr's TypeConstraint
                if (curExpr.isDereference()) {
                    Logging.info("TypeAliasPath", String.format("Try to merge memAlias into %s", curMergedCon));
                    var mayMemAliases = exprManager.fastGetMayMemAliases(curExpr);
                    for (var alias: mayMemAliases) {
                        if (alias == curExpr) {
                            continue;
                        }
                        var aliasCon = exprManager.getConstraint(alias);
                        if (aliasCon == null) {
                            continue;
                        }
                        var noConflict = curMergedCon.tryMerge(aliasCon);
                        if (!noConflict) {
                            Logging.warn("TypeAliasPath", String.format("Conflict when merging TypeConstraints in memAlias for %s and %s", curExpr, alias));
                        }
                    }
                }
            }

            // Merge backward constraints in the path
            if (i > 0) {
                var prevMergedCon = backwardMergedConstraints.get(i - 1);
                Logging.info("TypeAliasPath", String.format("Try to merge previous into current: %s -> %s", prevMergedCon, curMergedCon));
                Logging.info("TypeAliasPath", prevMergedCon.dumpLayout(0));
                Logging.info("TypeAliasPath", curMergedCon.dumpLayout(0));
                if (prevMergedCon.isEmpty()) {
                    backwardMergedConstraints.add(curMergedCon);
                    continue;
                } else if (curMergedCon.isEmpty()) {
                    backwardMergedConstraints.add(prevMergedCon);
                    continue;
                } else {
                    var noConflict = curMergedCon.tryMerge(prevMergedCon);
                    if (noConflict) {
                        backwardMergedConstraints.add(curMergedCon);
                        continue;
                    }
                    else {
                        Logging.warn("TypeAliasPath", String.format("Conflict when merging TypeConstraints on path for %s", curExpr));
                        // If conflict happens, we should return the conflict node
                        return Optional.of(node);
                    }
                }
            } else {
                backwardMergedConstraints.add(curMergedCon);
            }
        }

        // update finalConstraint
        finalConstraint = backwardMergedConstraints.get(backwardMergedConstraints.size() - 1);
        return Optional.empty();
    }


    public void createSubPathsOfLength(int length) {
        if (length < 1) {
            return;
        }

        for (int i = 0; i < nodes.size() - length + 1; i++) {
            var subPathNodes = nodes.subList(i, i + length);
            var hash = getPathsHashCode(subPathNodes);
            if (!subPathsOfLengthWithHash.containsKey(length)) {
                subPathsOfLengthWithHash.put(length, new HashMap<>());
            }
            if (!subPathsOfLengthWithHash.get(length).containsKey(hash)) {
                subPathsOfLengthWithHash.get(length).put(hash, subPathNodes);
            }
        }
    }

    public int getPathsHashCode(List<T> path) {
        int hash = 0;
        for (var t : path) {
            hash = 31 * hash + t.hashCode();
        }
        return hash;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append(String.format("Path-%s: ", shortUUID));
        builder.append(nodes.get(0));
        for (int i = 0; i < edges.size(); i++) {
            builder.append(String.format(" --- %s ---> ", edges.get(i).getType()));
            if (i + 1 < nodes.size()) {
                builder.append(nodes.get(i + 1));
            }
        }
        return builder.toString();
    }
}
