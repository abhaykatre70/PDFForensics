class DotGrid {
    constructor(canvasId, options = {}) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');

        // Configure default values according to the requested react component
        this.config = Object.assign({
            dotSize: 7,
            gap: 37,
            baseColor: '#271E37',
            activeColor: '#cdc9de',
            proximity: 120,
            shockRadius: 250,
            shockStrength: 5,
            resistance: 750,
            returnDuration: 1.5
        }, options);

        this.dots = [];
        this.mouse = { x: -1000, y: -1000 };
        this.click = { x: -1000, y: -1000, active: 0, maxStrength: this.config.shockStrength };

        this.resize();
        this.initDots();
        this.bindEvents();
        this.animate();
    }

    resize() {
        if (!this.canvas.parentElement) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = rect.width;
        this.height = rect.height;
        this.canvas.width = this.width;
        this.canvas.height = this.height;
        this.initDots();
    }

    initDots() {
        this.dots = [];
        const cols = Math.ceil(this.width / this.config.gap) + 2;
        const rows = Math.ceil(this.height / this.config.gap) + 2;
        const offsetX = (this.width - ((cols - 1) * this.config.gap)) / 2;
        const offsetY = (this.height - ((rows - 1) * this.config.gap)) / 2;

        for (let i = 0; i < cols; i++) {
            for (let j = 0; j < rows; j++) {
                const x = offsetX + i * this.config.gap;
                const y = offsetY + j * this.config.gap;
                this.dots.push({
                    ox: x,
                    oy: y,
                    x: x,
                    y: y,
                    vx: 0,
                    vy: 0
                });
            }
        }
    }

    bindEvents() {
        window.addEventListener('resize', () => this.resize());

        window.addEventListener('mousemove', (e) => {
            if (!this.canvas) return;
            const rect = this.canvas.getBoundingClientRect();
            // Calculate relative to the canvas
            this.mouse.x = e.clientX - rect.left;
            this.mouse.y = e.clientY - rect.top;
        });

        window.addEventListener('mouseleave', () => {
            this.mouse.x = -1000;
            this.mouse.y = -1000;
        });

        window.addEventListener('mousedown', (e) => {
            if (!this.canvas) return;
            // Prevent interaction if clicking on an interactive element like button or input
            const targetTag = e.target.tagName.toLowerCase();
            if (['button', 'a', 'input', 'textarea', 'select'].includes(targetTag) || e.target.closest('button, a, input, .upload-card')) {
                return;
            }

            const rect = this.canvas.getBoundingClientRect();

            // Check if click is actually inside or over the canvas bounds
            const clickX = e.clientX - rect.left;
            const clickY = e.clientY - rect.top;

            if (clickX >= 0 && clickX <= rect.width && clickY >= 0 && clickY <= rect.height) {
                this.click.x = clickX;
                this.click.y = clickY;
                this.click.active = 1.0;
            }
        });
    }

    animate() {
        this.ctx.clearRect(0, 0, this.width, this.height);

        // Spring constant and friction
        const k = 0.05 / this.config.returnDuration;
        const friction = this.config.resistance / 1000;

        // Shock wave expanding radius calculation
        const shockRadius = this.config.shockRadius;

        // expand shock wave based on time 
        if (this.click.active > 0) {
            this.click.active -= 0.02; // decay shockwave
            if (this.click.active <= 0) this.click.active = 0;
        }

        const currentShockRadius = shockRadius * (1 - this.click.active);

        for (let i = 0; i < this.dots.length; i++) {
            let dot = this.dots[i];

            let targetX = dot.ox;
            let targetY = dot.oy;

            // Mouse Repel
            const dx = this.mouse.x - dot.ox;
            const dy = this.mouse.y - dot.oy;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < this.config.proximity) {
                const force = (this.config.proximity - dist) / this.config.proximity;
                const angle = Math.atan2(dy, dx);
                targetX -= Math.cos(angle) * force * 15;
                targetY -= Math.sin(angle) * force * 15;
            }

            // Click Shockwave
            if (this.click.active > 0) {
                const cx = dot.ox - this.click.x;
                const cy = dot.oy - this.click.y;
                const cDist = Math.sqrt(cx * cx + cy * cy);
                const waveThickness = 40;

                if (Math.abs(cDist - currentShockRadius) < waveThickness) {
                    const force = (waveThickness - Math.abs(cDist - currentShockRadius)) / waveThickness;
                    const angle = Math.atan2(cy, cx);
                    // Push outwards
                    targetX += Math.cos(angle) * force * this.config.shockStrength * 10 * this.click.active;
                    targetY += Math.sin(angle) * force * this.config.shockStrength * 10 * this.click.active;
                }
            }

            // Spring Physics
            const ax = (targetX - dot.x) * k;
            const ay = (targetY - dot.y) * k;

            dot.vx += ax;
            dot.vy += ay;
            dot.vx *= friction;
            dot.vy *= friction;

            dot.x += dot.vx;
            dot.y += dot.vy;

            // Render
            const displacement = Math.sqrt((dot.x - dot.ox) ** 2 + (dot.y - dot.oy) ** 2);

            this.ctx.beginPath();
            this.ctx.arc(dot.x, dot.y, this.config.dotSize / 2, 0, Math.PI * 2);

            if (displacement > 1) {
                // Determine active shade
                const ratio = Math.min(displacement / 20, 1);
                this.ctx.fillStyle = this.config.activeColor;
                this.ctx.globalAlpha = 0.8 + (0.2 * ratio);
            } else {
                this.ctx.fillStyle = this.config.baseColor;
                this.ctx.globalAlpha = 0.7;
            }

            this.ctx.fill();
        }

        requestAnimationFrame(() => this.animate());
    }
}
