package tls

import (
	"crypto/tls"
	"reflect"
	"unsafe"
)

func (cs ConnectionState) Compatible() (tcs tls.ConnectionState) {
	cst := reflect.TypeOf(&cs).Elem()
	csv := reflect.ValueOf(&cs).Elem()
	tcsv := reflect.ValueOf(&tcs).Elem()

	for i := 0; i < cst.NumField(); i++ {
		fieldName := cst.Field(i).Name
		field := tcsv.FieldByName(fieldName)
		if !field.IsValid() || field.Kind() != csv.FieldByName(cst.Field(i).Name).Kind() {
			continue
		}

		if field.CanSet() {
			field.Set(csv.FieldByName(cst.Field(i).Name))
		} else {
			source := csv.FieldByName(cst.Field(i).Name)
			v := reflect.NewAt(source.Type(), unsafe.Pointer(source.UnsafeAddr())).Elem()
			reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(v)
		}
	}
	return
}

func ToConnectionState(tcs tls.ConnectionState) (cs ConnectionState) {
	tcst := reflect.TypeOf(&tcs).Elem()
	tcsv := reflect.ValueOf(&tcs).Elem()
	csv := reflect.ValueOf(&cs).Elem()

	for i := 0; i < tcst.NumField(); i++ {
		fieldName := tcst.Field(i).Name
		field := csv.FieldByName(fieldName)
		if !field.IsValid() || field.Kind() != tcsv.FieldByName(tcst.Field(i).Name).Kind() {
			continue
		}

		if field.CanSet() {
			field.Set(tcsv.FieldByName(tcst.Field(i).Name))
		} else {
			source := tcsv.FieldByName(tcst.Field(i).Name)
			v := reflect.NewAt(source.Type(), unsafe.Pointer(source.UnsafeAddr())).Elem()
			reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(v)
		}
	}
	return
}
