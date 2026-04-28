"""Deliberately duplicated code blocks for CPD/PMD testing.

Each function is identical — CPD should detect this as copy-paste duplication.
The blocks are large enough to exceed CPD's default minimum token threshold.
"""


def process_order_alpha(order_id: int, quantity: int, price: float) -> dict:
    subtotal = quantity * price
    tax_rate = 0.08
    tax = subtotal * tax_rate
    shipping_threshold = 50.0
    shipping_cost = 5.99 if subtotal < shipping_threshold else 0.0
    total_before_discount = subtotal + tax + shipping_cost
    discount_threshold = 10
    discount_rate = 0.1
    discount = total_before_discount * discount_rate if quantity > discount_threshold else 0.0
    final_total = total_before_discount - discount
    processing_fee = final_total * 0.02
    grand_total = final_total + processing_fee
    return {
        "order_id": order_id,
        "subtotal": subtotal,
        "tax": tax,
        "shipping": shipping_cost,
        "discount": discount,
        "processing_fee": processing_fee,
        "total": grand_total,
    }


def process_order_beta(order_id: int, quantity: int, price: float) -> dict:
    subtotal = quantity * price
    tax_rate = 0.08
    tax = subtotal * tax_rate
    shipping_threshold = 50.0
    shipping_cost = 5.99 if subtotal < shipping_threshold else 0.0
    total_before_discount = subtotal + tax + shipping_cost
    discount_threshold = 10
    discount_rate = 0.1
    discount = total_before_discount * discount_rate if quantity > discount_threshold else 0.0
    final_total = total_before_discount - discount
    processing_fee = final_total * 0.02
    grand_total = final_total + processing_fee
    return {
        "order_id": order_id,
        "subtotal": subtotal,
        "tax": tax,
        "shipping": shipping_cost,
        "discount": discount,
        "processing_fee": processing_fee,
        "total": grand_total,
    }


def process_order_gamma(order_id: int, quantity: int, price: float) -> dict:
    subtotal = quantity * price
    tax_rate = 0.08
    tax = subtotal * tax_rate
    shipping_threshold = 50.0
    shipping_cost = 5.99 if subtotal < shipping_threshold else 0.0
    total_before_discount = subtotal + tax + shipping_cost
    discount_threshold = 10
    discount_rate = 0.1
    discount = total_before_discount * discount_rate if quantity > discount_threshold else 0.0
    final_total = total_before_discount - discount
    processing_fee = final_total * 0.02
    grand_total = final_total + processing_fee
    return {
        "order_id": order_id,
        "subtotal": subtotal,
        "tax": tax,
        "shipping": shipping_cost,
        "discount": discount,
        "processing_fee": processing_fee,
        "total": grand_total,
    }
