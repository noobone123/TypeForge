package blueprint.base.dataflow.typeAlias;
import blueprint.base.dataflow.constraints.TypeConstraint;
import org.jgrapht.GraphPath;

import java.util.List;
import java.util.Map;

public class TypeAliasPath<T> {
    public GraphPath<T, TypeAliasGraph.TypeAliasEdge> path;
    public List<T> nodes;
    public Map<T, TypeConstraint> backwardConstraints;
    public Map<T, TypeConstraint> forwardConstraints;
    public TypeConstraint finalConstraint;

    public TypeAliasPath(GraphPath<T, TypeAliasGraph.TypeAliasEdge> path) {
        this.path = path;

        // update nodes;
        this.nodes = path.getVertexList();
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();
        for (T node: nodes) {
            builder.append(node.toString());
            builder.append(" -> ");
        }
        builder.append("END");
        return builder.toString();
    }
}
