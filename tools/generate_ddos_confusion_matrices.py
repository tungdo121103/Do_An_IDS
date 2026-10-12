from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


PROJECT_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_DIR / "reports" / "figures"
FONT_DIR = Path("C:/Windows/Fonts")

MATRICES = {
    "ddos_random_forest_confusion_matrix.png": {
        "title": "Confusion Matrix - Random Forest (DDoS)",
        "values": [[30000, 0], [13, 9987]],
    },
    "ddos_lightgbm_confusion_matrix.png": {
        "title": "Confusion Matrix - LightGBM (DDoS)",
        "values": [[29998, 2], [11, 9989]],
    },
}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "arialbd.ttf" if bold else "arial.ttf"
    return ImageFont.truetype(str(FONT_DIR / name), size)


def centered(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], text: str, text_font, fill: str) -> None:
    left, top, right, bottom = box
    bounds = draw.textbbox((0, 0), text, font=text_font)
    width = bounds[2] - bounds[0]
    height = bounds[3] - bounds[1]
    draw.text(
        ((left + right - width) / 2, (top + bottom - height) / 2 - bounds[1]),
        text,
        font=text_font,
        fill=fill,
    )


def blend(low: tuple[int, int, int], high: tuple[int, int, int], ratio: float) -> tuple[int, int, int]:
    return tuple(round(low[i] + (high[i] - low[i]) * ratio) for i in range(3))


def save_confusion_matrix(filename: str, title: str, values: list[list[int]]) -> None:
    canvas = Image.new("RGB", (1800, 1450), "white")
    draw = ImageDraw.Draw(canvas)
    draw.text((900, 70), title, font=font(54, True), fill="#111827", anchor="ma")

    grid_left, grid_top = 400, 300
    cell_w, cell_h = 520, 420
    max_value = max(max(row) for row in values)
    pale_blue = (239, 246, 255)
    dark_blue = (8, 81, 156)
    labels = ["BENIGN", "DDoS"]

    for index, label in enumerate(labels):
        centered(
            draw,
            (grid_left + index * cell_w, 200, grid_left + (index + 1) * cell_w, 285),
            label,
            font(36, True),
            "#334155",
        )
        centered(
            draw,
            (130, grid_top + index * cell_h, 375, grid_top + (index + 1) * cell_h),
            label,
            font(36, True),
            "#334155",
        )

    for row in range(2):
        for column in range(2):
            value = values[row][column]
            ratio = value / max_value if max_value else 0
            box = (
                grid_left + column * cell_w,
                grid_top + row * cell_h,
                grid_left + (column + 1) * cell_w,
                grid_top + (row + 1) * cell_h,
            )
            draw.rectangle(box, fill=blend(pale_blue, dark_blue, ratio), outline="white", width=8)
            centered(
                draw,
                box,
                f"{value:,}",
                font(60, True),
                "white" if ratio > 0.5 else "#111827",
            )

    centered(
        draw,
        (grid_left, 1170, grid_left + cell_w * 2, 1260),
        "Predicted label",
        font(38, True),
        "#111827",
    )
    vertical = Image.new("RGBA", (320, 90), (255, 255, 255, 0))
    vertical_draw = ImageDraw.Draw(vertical)
    vertical_draw.text((160, 45), "True label", font=font(38, True), fill="#111827", anchor="mm")
    vertical = vertical.rotate(90, expand=True)
    canvas.paste(vertical, (45, 560), vertical)

    draw.text(
        (900, 1360),
        "Rows: actual class   |   Columns: predicted class",
        font=font(28),
        fill="#64748b",
        anchor="mm",
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    canvas.save(OUTPUT_DIR / filename, format="PNG", dpi=(300, 300), optimize=True)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for filename, config in MATRICES.items():
        save_confusion_matrix(filename, config["title"], config["values"])
        print(OUTPUT_DIR / filename)


if __name__ == "__main__":
    main()
