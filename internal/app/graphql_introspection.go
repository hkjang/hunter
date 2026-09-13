package app

import (
	"sort"

	"github.com/vektah/gqlparser/v2/ast"
)

func graphType(t *ast.Type) any {
	if t == nil {
		return nil
	}
	return graphObject{Type: "__Type", TypeRef: t}
}
func (x *graphExecutor) introspection(o graphObject, f *ast.Field) (any, error) {
	include, _ := f.ArgumentMap(x.vars)["includeDeprecated"].(bool)
	switch o.Type {
	case "__Schema":
		switch f.Name {
		case "description":
			return "Hunter 인증 조회 API", nil
		case "queryType":
			return graphObject{Type: "__Type", Definition: hunterGraphQLSchema.Query}, nil
		case "mutationType", "subscriptionType":
			return nil, nil
		case "types":
			names := []string{}
			for name := range hunterGraphQLSchema.Types {
				names = append(names, name)
			}
			sort.Strings(names)
			values := []graphObject{}
			for _, name := range names {
				values = append(values, graphObject{Type: "__Type", Definition: hunterGraphQLSchema.Types[name]})
			}
			return values, nil
		case "directives":
			names := []string{}
			for name := range hunterGraphQLSchema.Directives {
				names = append(names, name)
			}
			sort.Strings(names)
			values := []graphObject{}
			for _, name := range names {
				values = append(values, graphObject{Type: "__Directive", Directive: hunterGraphQLSchema.Directives[name]})
			}
			return values, nil
		}
	case "__Type":
		d := o.Definition
		t := o.TypeRef
		if t != nil {
			if t.NonNull {
				if f.Name == "kind" {
					return "NON_NULL", nil
				}
				if f.Name == "ofType" {
					copy := *t
					copy.NonNull = false
					return graphType(&copy), nil
				}
				return nil, nil
			}
			if t.Elem != nil {
				if f.Name == "kind" {
					return "LIST", nil
				}
				if f.Name == "ofType" {
					return graphType(t.Elem), nil
				}
				return nil, nil
			}
			d = hunterGraphQLSchema.Types[t.NamedType]
		}
		if d == nil {
			return nil, nil
		}
		switch f.Name {
		case "kind":
			return string(d.Kind), nil
		case "name":
			return d.Name, nil
		case "description":
			return d.Description, nil
		case "ofType":
			return nil, nil
		case "specifiedByURL":
			if dir := d.Directives.ForName("specifiedBy"); dir != nil {
				if a := dir.Arguments.ForName("url"); a != nil {
					return a.Value.Raw, nil
				}
			}
			return nil, nil
		case "isOneOf":
			return d.Directives.ForName("oneOf") != nil, nil
		case "fields":
			if d.Kind != ast.Object && d.Kind != ast.Interface {
				return nil, nil
			}
			v := []graphObject{}
			for _, field := range d.Fields {
				if len(field.Name) > 1 && field.Name[:2] == "__" {
					continue
				}
				deprecated, _ := graphDeprecated(field.Directives)
				if !include && deprecated {
					continue
				}
				v = append(v, graphObject{Type: "__Field", Field: field})
			}
			return v, nil
		case "inputFields":
			if d.Kind != ast.InputObject {
				return nil, nil
			}
			v := []graphObject{}
			for _, field := range d.Fields {
				deprecated, _ := graphDeprecated(field.Directives)
				if !include && deprecated {
					continue
				}
				v = append(v, graphObject{Type: "__InputValue", Field: field})
			}
			return v, nil
		case "interfaces":
			if d.Kind != ast.Object && d.Kind != ast.Interface {
				return nil, nil
			}
			v := []graphObject{}
			for _, name := range d.Interfaces {
				v = append(v, graphObject{Type: "__Type", Definition: hunterGraphQLSchema.Types[name]})
			}
			return v, nil
		case "possibleTypes":
			if d.Kind != ast.Union && d.Kind != ast.Interface {
				return nil, nil
			}
			v := []graphObject{}
			for _, d := range hunterGraphQLSchema.PossibleTypes[d.Name] {
				v = append(v, graphObject{Type: "__Type", Definition: d})
			}
			return v, nil
		case "enumValues":
			if d.Kind != ast.Enum {
				return nil, nil
			}
			v := []graphObject{}
			for _, ev := range d.EnumValues {
				deprecated, _ := graphDeprecated(ev.Directives)
				if !include && deprecated {
					continue
				}
				v = append(v, graphObject{Type: "__EnumValue", Enum: ev})
			}
			return v, nil
		}
	case "__Field":
		v := o.Field
		deprecated, reason := graphDeprecated(v.Directives)
		switch f.Name {
		case "name":
			return v.Name, nil
		case "description":
			return v.Description, nil
		case "type":
			return graphType(v.Type), nil
		case "isDeprecated":
			return deprecated, nil
		case "deprecationReason":
			return reason, nil
		case "args":
			args := []graphObject{}
			for _, arg := range v.Arguments {
				dep, _ := graphDeprecated(arg.Directives)
				if !include && dep {
					continue
				}
				args = append(args, graphObject{Type: "__InputValue", Argument: arg})
			}
			return args, nil
		}
	case "__InputValue":
		var name, description string
		var typ *ast.Type
		var value *ast.Value
		var dirs ast.DirectiveList
		if a := o.Argument; a != nil {
			name, description, typ, value, dirs = a.Name, a.Description, a.Type, a.DefaultValue, a.Directives
		} else if f := o.Field; f != nil {
			name, description, typ, value, dirs = f.Name, f.Description, f.Type, f.DefaultValue, f.Directives
		}
		dep, reason := graphDeprecated(dirs)
		switch f.Name {
		case "name":
			return name, nil
		case "description":
			return description, nil
		case "type":
			return graphType(typ), nil
		case "defaultValue":
			return graphDefault(value), nil
		case "isDeprecated":
			return dep, nil
		case "deprecationReason":
			return reason, nil
		}
	case "__EnumValue":
		v := o.Enum
		dep, reason := graphDeprecated(v.Directives)
		switch f.Name {
		case "name":
			return v.Name, nil
		case "description":
			return v.Description, nil
		case "isDeprecated":
			return dep, nil
		case "deprecationReason":
			return reason, nil
		}
	case "__Directive":
		v := o.Directive
		switch f.Name {
		case "name":
			return v.Name, nil
		case "description":
			return v.Description, nil
		case "isRepeatable":
			return v.IsRepeatable, nil
		case "locations":
			return v.Locations, nil
		case "args":
			args := []graphObject{}
			for _, arg := range v.Arguments {
				dep, _ := graphDeprecated(arg.Directives)
				if !include && dep {
					continue
				}
				args = append(args, graphObject{Type: "__InputValue", Argument: arg})
			}
			return args, nil
		}
	}
	return nil, nil
}
