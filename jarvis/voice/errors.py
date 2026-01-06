class VoiceError(RuntimeError):
    pass


class DependencyMissing(VoiceError):
    pass


class ModelNotConfigured(VoiceError):
    pass


class AudioError(VoiceError):
    pass


class STTError(VoiceError):
    pass


class TTSError(VoiceError):
    pass


class VoiceTimeout(VoiceError):
    pass

