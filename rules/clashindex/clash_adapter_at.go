package clashindex

func (t *Table) AdapterAt(i int) string {
	kind, _, target, _, ok := t.x.entry(i)
	if !ok {
		return ""
	}
	if kind == kindOther {
		return t.At(i).Adapter()
	}
	name, _ := t.x.target(target)
	return name
}

func (t *Table) ClashNamedOnly(i int) bool {
	kind, _, _, _, ok := t.x.entry(i)
	return ok && (kind == kindDomain || kind == kindSuffix || kind == kindKeyword)
}
