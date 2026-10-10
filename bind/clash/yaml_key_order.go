package clash

import "go.yaml.in/yaml/v3"

func restoreSourceKeyOrder(source, transformed string) string {
	return restoreKeyOrderFrom(transformed, source)
}

func restoreKeyOrderFrom(transformed string, references ...string) string {
	documents := make([]*yaml.Node, 0, len(references))
	for _, reference := range references {
		var document yaml.Node
		if err := yaml.Unmarshal([]byte(reference), &document); err != nil {
			continue
		}
		documents = append(documents, &document)
	}
	text, _ := restoreKeyOrderFromDocuments(transformed, documents)
	return text
}

func restoreKeyOrderFromDocuments(transformed string, references []*yaml.Node) (string, *yaml.Node) {
	var transformedRoot yaml.Node
	if err := yaml.Unmarshal([]byte(transformed), &transformedRoot); err != nil {
		return transformed, nil
	}
	if len(transformedRoot.Content) == 0 {
		return transformed, nil
	}

	roots := make([]*yaml.Node, 0, len(references))
	for _, reference := range references {
		if reference == nil || len(reference.Content) == 0 {
			continue
		}
		roots = append(roots, reference.Content[0])
	}
	if len(roots) == 0 {
		return transformed, &transformedRoot
	}

	reorderNodeFrom(roots, transformedRoot.Content[0], 0)

	standIns := standInAstralInNode(&transformedRoot)
	out, err := yaml.Marshal(&transformedRoot)
	if err != nil {
		return transformed, nil
	}
	standIns.restoreInNode(&transformedRoot)
	if standIns.escapedIn(string(out)) {
		return standIns.restore(string(out)), nil
	}
	if !treeReadsBack(&transformedRoot) {
		return standIns.restore(string(out)), nil
	}
	return standIns.restore(string(out)), &transformedRoot
}

const maxKeyOrderDepth = 64

func reorderNodeFrom(references []*yaml.Node, transformed *yaml.Node, depth int) {
	if depth > maxKeyOrderDepth || transformed == nil || transformed.Kind == yaml.AliasNode {
		return
	}
	usable := references[:0:0]
	for _, reference := range references {
		if reference == nil || reference.Kind == yaml.AliasNode || reference.Kind != transformed.Kind {
			continue
		}
		usable = append(usable, reference)
	}
	if len(usable) == 0 {
		return
	}

	switch transformed.Kind {
	case yaml.DocumentNode:
		if len(transformed.Content) == 0 {
			return
		}
		next := make([]*yaml.Node, 0, len(usable))
		for _, reference := range usable {
			if len(reference.Content) > 0 {
				next = append(next, reference.Content[0])
			}
		}
		reorderNodeFrom(next, transformed.Content[0], depth+1)
	case yaml.SequenceNode:
		for i := 0; i < len(transformed.Content); i++ {
			next := make([]*yaml.Node, 0, len(usable))
			for _, reference := range usable {
				if i < len(reference.Content) {
					next = append(next, reference.Content[i])
				}
			}
			if len(next) > 0 {
				reorderNodeFrom(next, transformed.Content[i], depth+1)
			}
		}
	case yaml.MappingNode:
		const perReference = 1 << 20
		sourceOrder := map[string]int{}
		for r, reference := range usable {
			for i := 0; i+1 < len(reference.Content); i += 2 {
				key := reference.Content[i]
				if key.Kind != yaml.ScalarNode {
					continue
				}
				if _, seen := sourceOrder[key.Value]; !seen {
					sourceOrder[key.Value] = r*perReference + i
				}
			}
		}

		type pair struct {
			key, value *yaml.Node
			rank       int
			position   int
		}
		const addedByTransform = 1 << 30
		pairs := make([]pair, 0, len(transformed.Content)/2)
		for i := 0; i+1 < len(transformed.Content); i += 2 {
			key, value := transformed.Content[i], transformed.Content[i+1]
			rank := addedByTransform + i
			if key.Kind == yaml.ScalarNode {
				if at, ok := sourceOrder[key.Value]; ok {
					rank = at
				}
			}
			pairs = append(pairs, pair{key: key, value: value, rank: rank, position: i})
		}

		for i := 1; i < len(pairs); i++ {
			for j := i; j > 0 && pairs[j-1].rank > pairs[j].rank; j-- {
				pairs[j-1], pairs[j] = pairs[j], pairs[j-1]
			}
		}

		content := make([]*yaml.Node, 0, len(pairs)*2)
		for _, p := range pairs {
			content = append(content, p.key, p.value)
		}
		if len(transformed.Content)%2 == 1 {
			content = append(content, transformed.Content[len(transformed.Content)-1])
		}
		transformed.Content = content

		childrenOf := func(reference *yaml.Node, key string) *yaml.Node {
			for i := 0; i+1 < len(reference.Content); i += 2 {
				if k := reference.Content[i]; k.Kind == yaml.ScalarNode && k.Value == key {
					return reference.Content[i+1]
				}
			}
			return nil
		}
		for i := 0; i+1 < len(transformed.Content); i += 2 {
			key := transformed.Content[i]
			if key.Kind != yaml.ScalarNode {
				continue
			}
			next := make([]*yaml.Node, 0, len(usable))
			for _, reference := range usable {
				if child := childrenOf(reference, key.Value); child != nil {
					next = append(next, child)
				}
			}
			if len(next) > 0 {
				reorderNodeFrom(next, transformed.Content[i+1], depth+1)
			}
		}
	}
}
