namespace ProsperoPkgTool.Containers;

/// <summary>Why a read failed, when the reader can tell. Kept separate from the message text.</summary>
public enum ProsperoErrorKind
{
    /// <summary>The bytes are readable but use a layout/encoding this reader does not implement.</summary>
    Unsupported
}

/// <summary>
/// Classifies engine read failures without changing the exception type. <see cref="InvalidDataException"/>
/// is sealed and widely caught across the reader (dialect probing relies on it), so the kind travels in
/// <see cref="Exception.Data"/> instead. Callers can then tell "unsupported format" apart from a wrong
/// key or corruption and report the real cause.
/// </summary>
public static class ProsperoErrorInfo
{
    private const string Key = "Prospero.ErrorKind";

    /// <summary>Creates an <see cref="InvalidDataException"/> marked as an unsupported format/layout.</summary>
    public static InvalidDataException Unsupported(string message)
    {
        var exception = new InvalidDataException(message);
        exception.Data[Key] = ProsperoErrorKind.Unsupported;
        return exception;
    }

    /// <summary>True when the exception (or any inner exception) is a marked unsupported-format failure.</summary>
    public static bool IsUnsupported(Exception? exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
            if (current.Data.Contains(Key) && current.Data[Key] is ProsperoErrorKind.Unsupported)
                return true;
        return false;
    }
}
