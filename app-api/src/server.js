require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1";

app.use(cors());
app.use(express.json());

// Health-check endpoint
app.get("/health", (req, res) => {
    res.json({
        success: true,
        message: "Mini Sherlocq API is running",
    });
});

app.post("/api/ask", async (req, res) => {
    const { question } = req.body ?? {};

    if (question === undefined || question === null) {
        return res.status(400).json({
            success: false,
            error: {
                code: "QUESTION_REQUIRED",
                message: "Question is required",
            },
        });
    }

    if (typeof question !== "string") {
        return res.status(400).json({
            success: false,
            error: {
                code: "INVALID_QUESTION_TYPE",
                message: "Question must be a string",
            },
        });
    }

    const trimmedQuestion = question.trim();

    if (!trimmedQuestion) {
        return res.status(400).json({
            success: false,
            error: {
                code: "QUESTION_EMPTY",
                message: "Question cannot be empty",
            },
        });
    }

    if (trimmedQuestion.length > 2000) {
        return res.status(400).json({
            success: false,
            error: {
                code: "QUESTION_TOO_LONG",
                message: "Question cannot exceed 2000 characters",
            },
        });
    }


    try {

        const response = await fetch(
            "https://openrouter.ai/api/v1/chat/completions",
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    model: "openrouter/free",
                    messages: [
                        {
                            role: "user",
                            content: trimmedQuestion,
                        },
                    ],
                }),
                signal: AbortSignal.timeout(30000),
            }
        );

        const result = await response.json();

        if (!response.ok) {
            console.error("OpenRouter API error:", result);

            throw new Error(
                result?.error?.message || `OpenRouter returned HTTP ${response.status}`
            );
        }

        const answer = result.choices?.[0]?.message?.content;

        if (!answer || typeof answer !== "string") {
            throw new Error("OpenRouter returned an empty response");
        }

        return res.status(200).json({
            success: true,
            data: {
                question: trimmedQuestion,
                answer,
            },
        });

    } catch (error) {
        console.error("OpenRouter API error:", error.message);

        return res.status(502).json({
            success: false,
            error: {
                code: "AI_SERVICE_ERROR",
                message: "Unable to generate an answer right now. Please try again.",
            },
        });
    }

});

app.use((err, req, res, next) => {
    if (
        err instanceof SyntaxError &&
        err.status === 400 &&
        "body" in err
    ) {
        return res.status(400).json({
            success: false,
            error: {
                code: "INVALID_JSON",
                message: "Request body contains invalid JSON",
            },
        });
    }

    next(err);
});

app.use((err, req, res, next) => {
    console.error("Unexpected API error:", err);

    if (res.headersSent) {
        return next(err);
    }

    return res.status(500).json({
        success: false,
        error: {
            code: "INTERNAL_SERVER_ERROR",
            message: "Something went wrong on the server",
        },
    });
});

app.listen(PORT, HOST, () => {
    console.log(`App API running at http://${HOST}:${PORT}`);
});
