//go:build ignore

package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	sizes := []int{16, 32, 48, 256}
	var pngs [][]byte
	for _, sz := range sizes {
		img := drawIcon(sz)
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			panic(err)
		}
		pngs = append(pngs, buf.Bytes())
		if sz == 256 {
			if err := os.WriteFile("web/icon.png", buf.Bytes(), 0o644); err != nil {
				panic(err)
			}
		}
	}
	var out bytes.Buffer
	binary.Write(&out, binary.LittleEndian, uint16(0))
	binary.Write(&out, binary.LittleEndian, uint16(1))
	binary.Write(&out, binary.LittleEndian, uint16(len(pngs)))
	offset := 6 + 16*len(pngs)
	for i, p := range pngs {
		side := sizes[i]
		if side >= 256 {
			side = 0
		}
		out.WriteByte(byte(side))
		out.WriteByte(byte(side))
		out.WriteByte(0)
		out.WriteByte(0)
		binary.Write(&out, binary.LittleEndian, uint16(1))
		binary.Write(&out, binary.LittleEndian, uint16(32))
		binary.Write(&out, binary.LittleEndian, uint32(len(p)))
		binary.Write(&out, binary.LittleEndian, uint32(offset))
		offset += len(p)
	}
	for _, p := range pngs {
		out.Write(p)
	}
	if err := os.WriteFile("icon.ico", out.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func drawIcon(size int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{26, 35, 50, 255}
	edge := color.RGBA{91, 141, 239, 255}
	line := color.RGBA{176, 204, 255, 255}
	mark := color.RGBA{61, 220, 151, 255}
	pad := float64(size) * 0.04
	rad := float64(size) * 0.28
	stroke := float64(max(1, size/16))
	paintRound(dst, pad, pad, float64(size)-pad, float64(size)-pad, rad, edge)
	paintRound(dst, pad+stroke, pad+stroke, float64(size)-pad-stroke, float64(size)-pad-stroke, rad-stroke, bg)
	lh := max(1, size/14)
	gap := max(lh+2, size/6)
	x0 := size / 5
	y0 := size / 4
	w := size * 9 / 20
	fillInside(dst, image.Rect(x0, y0, x0+w, y0+lh), line)
	fillInside(dst, image.Rect(x0, y0+gap, x0+w, y0+gap+lh), line)
	s := max(2, size/5)
	inset := max(2, size/7)
	fillInside(dst, image.Rect(size-inset-s, size-inset-s, size-inset, size-inset), mark)
	return dst
}

func paintRound(dst *image.RGBA, x0, y0, x1, y1, rad float64, c color.RGBA) {
	b := dst.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			cov := roundCover(float64(x)+0.5, float64(y)+0.5, x0, y0, x1, y1, rad)
			if cov <= 0 {
				continue
			}
			dst.SetRGBA(x, y, color.RGBA{c.R, c.G, c.B, uint8(float64(c.A) * cov)})
		}
	}
}

func roundCover(px, py, x0, y0, x1, y1, rad float64) float64 {
	if rad < 0 {
		rad = 0
	}
	cx := (x0 + x1) / 2
	cy := (y0 + y1) / 2
	hw := (x1 - x0) / 2
	hh := (y1 - y0) / 2
	qx := math.Abs(px-cx) - (hw - rad)
	qy := math.Abs(py-cy) - (hh - rad)
	ox := math.Max(qx, 0)
	oy := math.Max(qy, 0)
	dist := math.Hypot(ox, oy) + math.Min(math.Max(qx, qy), 0) - rad
	if dist <= -0.75 {
		return 1
	}
	if dist >= 0.75 {
		return 0
	}
	return (0.75 - dist) / 1.5
}

func fillInside(dst *image.RGBA, r image.Rectangle, c color.RGBA) {
	r = r.Intersect(dst.Bounds())
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if dst.RGBAAt(x, y).A < 200 {
				continue
			}
			dst.SetRGBA(x, y, c)
		}
	}
}

func fill(dst *image.RGBA, c color.RGBA) {
	for i := 0; i < len(dst.Pix); i += 4 {
		dst.Pix[i], dst.Pix[i+1], dst.Pix[i+2], dst.Pix[i+3] = c.R, c.G, c.B, c.A
	}
}

func fillRect(dst *image.RGBA, r image.Rectangle, c color.RGBA) {
	r = r.Intersect(dst.Bounds())
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			dst.SetRGBA(x, y, c)
		}
	}
}

func stroke(dst *image.RGBA, r image.Rectangle, t int, c color.RGBA) {
	fillRect(dst, image.Rect(r.Min.X, r.Min.Y, r.Max.X, r.Min.Y+t), c)
	fillRect(dst, image.Rect(r.Min.X, r.Max.Y-t, r.Max.X, r.Max.Y), c)
	fillRect(dst, image.Rect(r.Min.X, r.Min.Y, r.Min.X+t, r.Max.Y), c)
	fillRect(dst, image.Rect(r.Max.X-t, r.Min.Y, r.Max.X, r.Max.Y), c)
}
