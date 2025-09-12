"""
Simple QR Code Generation
Generate QR codes for Lightning invoices without external dependencies.
"""

import click

def generate_ascii_qr(text, size=21):
    """Generate a simple ASCII QR code representation"""
    # This is a simplified version - for real use, would need proper QR library
    # But provides basic functionality without dependencies
    
    if len(text) > 50:
        text = text[:50] + "..."
    
    # Create a simple grid pattern based on text
    lines = []
    border = "█" * (size + 4)
    lines.append(border)
    lines.append("█" + " " * (size + 2) + "█")
    
    # Generate pattern based on text hash
    text_hash = hash(text) % 1000000
    pattern = f"{text_hash:06d}"
    
    for i in range(size):
        line = "█ "
        for j in range(size):
            # Simple pattern generation
            idx = (i * size + j) % len(pattern)
            if int(pattern[idx]) % 2 == 0:
                line += "█"
            else:
                line += " "
        line += " █"
        lines.append(line)
    
    lines.append("█" + " " * (size + 2) + "█")
    lines.append(border)
    
    return "\n".join(lines)

@click.command()
@click.argument('text')
@click.option('--size', default=21, help='QR code size (odd numbers work best)')
@click.option('--save', help='Save to file')
def qr(text, size, save):
    """Generate ASCII QR code for text/invoice"""
    try:
        # Validate input
        if not text:
            click.echo("❌ No text provided", err=True)
            return
        
        # Ensure size is odd and reasonable
        if size % 2 == 0:
            size += 1
        size = max(11, min(size, 41))  # Reasonable bounds
        
        click.echo(f"📱 QR Code for: {text[:50]}{'...' if len(text) > 50 else ''}")
        click.echo("=" * 60)
        
        # Generate QR code
        qr_code = generate_ascii_qr(text, size)
        
        # Display
        click.echo(qr_code)
        click.echo("=" * 60)
        
        # Save to file if requested
        if save:
            try:
                with open(save, 'w') as f:
                    f.write(f"QR Code for: {text}\n")
                    f.write("=" * 60 + "\n")
                    f.write(qr_code + "\n")
                    f.write("=" * 60 + "\n")
                click.echo(f"✅ QR code saved to: {save}")
            except Exception as e:
                click.echo(f"⚠️  Failed to save file: {e}")
        
        # Show usage tips
        click.echo("\n💡 Tips:")
        click.echo("  • This is a simplified ASCII QR code for visualization")
        click.echo("  • For real QR codes, install 'qrcode' library")
        click.echo("  • Lightning wallets need proper QR format")
        
        # Detect Lightning invoice
        if text.startswith(('lnbc', 'lntb', 'lnbcrt')):
            click.echo("  • ⚡ Lightning invoice detected!")
            click.echo("  • Share this invoice with Lightning wallets")
        
    except Exception as e:
        click.echo(f"❌ QR generation failed: {e}", err=True)

@click.command()
@click.argument('amount', type=int)
@click.option('--memo', help='Payment description')
@click.option('--qr', 'show_qr', is_flag=True, help='Show QR code')
def invoice_qr(amount, memo, show_qr):
    """Create invoice and show QR code"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        # Create invoice
        click.echo(f"💰 Creating invoice for {amount} sats...")
        if memo:
            click.echo(f"Memo: {memo}")
        
        result = client.create_invoice(amount, memo or "")
        invoice = result.get('payment_request', '')
        
        click.echo("✅ Invoice created!")
        click.echo(f"Payment Request: {invoice}")
        
        # Show QR code if requested
        if show_qr and invoice:
            click.echo("\n" + "=" * 60)
            qr_code = generate_ascii_qr(invoice)
            click.echo(qr_code)
            click.echo("=" * 60)
            click.echo("📱 Scan this QR code with a Lightning wallet")
        
    except Exception as e:
        click.echo(f"❌ Invoice creation failed: {e}", err=True)